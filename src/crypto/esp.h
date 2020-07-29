/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/* Number of packets that be queued to a crypto thread */
#ifndef ESP_H
#define ESP_H

#include <netinet/udp.h>
#include <rte_mbuf.h>
#include <stdbool.h>
#include <stdint.h>

#include "crypto_sadb.h"

struct crypto_overhead;
struct rte_mbuf;
struct sadb_sa;
struct udphdr;

int esp_input(int family, struct rte_mbuf *m, struct sadb_sa *sa,
	      uint32_t *bytes, uint8_t *new_family);

int esp_output(struct rte_mbuf *m,  uint8_t family, void *l3hdr,
	       struct sadb_sa *sa, uint32_t *bytes);
int esp_output6(struct rte_mbuf *m, uint8_t family, void *l3hdr,
		struct sadb_sa *sa, uint32_t *bytes);

/*
 * RFC 4303 requires the pad length and next header fields to be right aligned
 * within a 4-byte word.
 */
#define ESP_PAYLOAD_MIN_ALIGN 4

/*
 * Returns the (minimum) length of the properly aligned ESP payload area
 * (everything after ESP header and before ESP trailer).
 */
uint16_t esp_payload_padded_len(const struct crypto_overhead *overhead,
				uint16_t tot_len);

int esp_replay_check(const uint8_t *esp, const struct sadb_sa *sa);
void esp_replay_advance(const uint8_t *esp, struct sadb_sa *sa);

/*
 * Returns true if packet requires crypto processing, false otherwise
 */
bool udp_esp_dp_interesting(const struct udphdr *udp, uint32_t *spi);

/*
 * API to invoke openssl implementation of encryption
 */
int esp_generate_chain(struct sadb_sa *sa, struct rte_mbuf *mbuf,
		       unsigned int l3_hdr_len, unsigned char *esp,
		       unsigned char *iv, uint32_t text_total_len,
		       int8_t encrypt);

#endif /* ESP_H */
