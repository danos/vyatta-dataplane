/*-
 * Copyright (c) 2020-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef CRYPTO_RTE_PMD_H

#define CRYPTO_RTE_PMD_H

#include <stdbool.h>
#include <linux/xfrm.h>
#include <rte_cryptodev.h>

#define BITS_PER_BYTE     8

struct crypto_session;
struct sadb_sa;
struct crypto_pkt_ctx;

int crypto_rte_setup(void);

void crypto_rte_shutdown(void);

int
crypto_rte_set_session_parameters(struct crypto_session *ctx,
				  const struct xfrm_algo *algo_crypt,
				  const struct xfrm_algo_auth *algo_trunc_auth,
				  const struct xfrm_algo *algo_auth);

/*
 * Crypto devices to instantiate in descending order of priority.
 * Whenever there is a need to instantiate a crypto device, the
 * available devices/drivers are checked starting with the first in this
 * list.
 */
enum cryptodev_type {
	CRYPTODEV_MIN,
	CRYPTODEV_AESNI_GCM = CRYPTODEV_MIN,
	CRYPTODEV_AESNI_MB,
	CRYPTODEV_NULL,
	CRYPTODEV_OPENSSL,
	CRYPTODEV_MAX
};

#define MAX_CRYPTO_PMD 128

unsigned int crypto_rte_dev_cnt(enum cryptodev_type type);

int crypto_rte_select_pmd_type(enum rte_crypto_cipher_algorithm cipher_algo,
			       enum rte_crypto_aead_algorithm aead_algo,
			       enum cryptodev_type *dev_type,
			       bool *setup_openssl);

int crypto_rte_create_pmd(int cpu_socket, uint8_t pmd_dev_id,
			  enum cryptodev_type dev_type, char dev_name[],
			  uint8_t max_name_len, int *rte_dev_id);

int crypto_rte_destroy_pmd(enum cryptodev_type dev_type, char dev_name[],
			   int pmd_dev_id);

int crypto_rte_setup_session(struct crypto_session *session,
			     enum cryptodev_type dev_type,
			     uint8_t rte_cdev_id);

int crypto_rte_destroy_session(struct crypto_session *session,
			       uint8_t rte_cdev_id);

int crypto_rte_op_alloc(struct rte_crypto_op *cops[], uint16_t count);

void crypto_rte_op_free(struct rte_crypto_op *cops[], uint16_t count);

uint16_t crypto_rte_xform_packets(struct crypto_pkt_ctx *ctx_arr[],
				  uint16_t count);

#endif /* CRYPTO_RTE_PMD_H */
