/*-
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <rte_bus_vdev.h>
#include <rte_cryptodev.h>
#include <rte_lcore.h>
#include <rte_mempool.h>

#include "crypto_defs.h"
#include "vplane_log.h"
#include "compiler.h"
#include "crypto.h"
#include "crypto_internal.h"
#include "crypto_rte_pmd.h"

/*
 * Support for 16K sessions ( = 8K tunnels )
 */
#define CRYPTO_MAX_SESSIONS (1 << 14)
#define CRYPTO_SESSION_POOL_CACHE_SIZE 512

#define MAX_CRYPTO_OPS 8192
#define CRYPTO_OP_POOL_CACHE_SIZE 256

/* per session (SA) data structure used to set up operations with PMDs */
static struct rte_mempool *crypto_session_pool;

/* per packet crypto op pool. This may eventually subsume crypto_pkt_ctx */
static struct rte_mempool *crypto_op_pool;

int crypto_rte_setup(void)
{
	int err = 0;
	int socket = rte_lcore_to_socket_id(rte_get_master_lcore());

	/*
	 * allocate generic session context pool
	 */
	crypto_session_pool = rte_cryptodev_sym_session_pool_create(
		"crypto_session_pool", CRYPTO_MAX_SESSIONS, 0,
		CRYPTO_SESSION_POOL_CACHE_SIZE, 0, socket);
	if (!crypto_session_pool) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not allocate crypto session pool\n");
		return -ENOMEM;
	}

	crypto_op_pool = rte_crypto_op_pool_create("crypto_op_pool",
						   RTE_CRYPTO_OP_TYPE_SYMMETRIC,
						   MAX_CRYPTO_OPS,
						   CRYPTO_OP_POOL_CACHE_SIZE,
						   CRYPTO_MAX_IV_LENGTH,
						   socket);
	if (!crypto_op_pool) {
		RTE_LOG(ERR, DATAPLANE, "Could not set up crypto op pool\n");
		err = -ENOMEM;
		goto fail;
	}

	return 0;

fail:
	rte_mempool_free(crypto_session_pool);
	return err;
}

void crypto_rte_shutdown(void)
{
	rte_mempool_free(crypto_session_pool);
	rte_mempool_free(crypto_op_pool);
}

#define BITS_PER_BYTE     8

struct cipher_algo_table {
	const char *name;
	enum rte_crypto_cipher_algorithm cipher_algo;
	uint8_t iv_len;
};

static const struct cipher_algo_table cipher_algorithms[] = {
	{ "cbc(aes)",         RTE_CRYPTO_CIPHER_AES_CBC,
	  IPSEC_AES_CBC_IV_SIZE },
	{ "cbc(des3_ede)",    RTE_CRYPTO_CIPHER_3DES_CBC,
	  IPSEC_3DES_IV_SIZE    },
	{ "eNULL",            RTE_CRYPTO_CIPHER_NULL,
	  0                     },
	{ "ecb(cipher_null)", RTE_CRYPTO_CIPHER_NULL,
	  0                     }
};

struct md_algo_table {
	const char *name;
	enum rte_crypto_auth_algorithm auth_algo;
};

static const struct md_algo_table md_algorithms[] = {
	{ "hmac(sha1)",		RTE_CRYPTO_AUTH_SHA1         },
	{ "hmac(sha256)",	RTE_CRYPTO_AUTH_SHA256_HMAC  },
	{ "hmac(sha384)",	RTE_CRYPTO_AUTH_SHA384_HMAC  },
	{ "hmac(sha512)",	RTE_CRYPTO_AUTH_SHA512_HMAC  },
	{ "hmac(md5)",		RTE_CRYPTO_AUTH_MD5          },
	{ "rfc4106(gcm(aes))",  RTE_CRYPTO_AUTH_NULL         },
	{ "aNULL",		RTE_CRYPTO_AUTH_NULL         }
};

static const char *cryptodev_names[CRYPTODEV_MAX] = {
	[CRYPTODEV_AESNI_MB]   = "crypto_aesni_mb",
	[CRYPTODEV_AESNI_GCM]  = "crypto_aesni_gcm",
	[CRYPTODEV_NULL]       = "crypto_null",
	[CRYPTODEV_OPENSSL]    = "crypto_openssl",
};

static int crypto_rte_setup_aes_gcm_cipher(struct crypto_session *ctx,
					   const struct xfrm_algo *algo_crypt)
{
	uint16_t key_len = algo_crypt->alg_key_len / BITS_PER_BYTE;

	key_len -= AES_GCM_NONCE_LENGTH;
	ctx->aead_algo = RTE_CRYPTO_AEAD_AES_GCM;
	ctx->nonce_len = AES_GCM_NONCE_LENGTH;
	ctx->key_len = key_len;
	ctx->iv_len = AES_GCM_IV_LENGTH;

	/* setup AES-GCM according to RFC4106 */
	if (key_len < 4) {
		RTE_LOG(ERR, DATAPLANE,
			"key_len too small: %d\n", key_len);
		return -EINVAL;
	}

	if (key_len != 16 && key_len != 32) {
		RTE_LOG(ERR, DATAPLANE,
			"Unsupported gcm(aes) key size: %d\n",
			key_len);
		ctx->cipher_name = "gcm(aes) unknown";
		return -EINVAL;
	}

	if (key_len > ARRAY_SIZE(ctx->key)) {
		RTE_LOG(ERR, DATAPLANE,
			"Unexpected encryption key len: %d\n", key_len);
		return -EINVAL;
	}
	memcpy(ctx->key, algo_crypt->alg_key, ctx->key_len);
	memcpy(ctx->nonce, algo_crypt->alg_key + ctx->key_len,
	       ctx->nonce_len);
	return 0;
}

static int crypto_rte_set_cipher(struct crypto_session *ctx,
				 const struct xfrm_algo *algo_crypt)
{
	const char *algo_name = algo_crypt->alg_name;
	uint16_t key_len = algo_crypt->alg_key_len / BITS_PER_BYTE;
	int err;

	ctx->cipher_algo = RTE_CRYPTO_CIPHER_LIST_END;
	if (strcmp("rfc4106(gcm(aes))", algo_name) == 0) {
		err = crypto_rte_setup_aes_gcm_cipher(ctx, algo_crypt);
		if (err)
			return err;
	} else {
		for (uint8_t i = 0; i < ARRAY_SIZE(cipher_algorithms); i++)
			if (!strcmp(cipher_algorithms[i].name, algo_name)) {
				ctx->cipher_algo =
					cipher_algorithms[i].cipher_algo;
				ctx->iv_len = cipher_algorithms[i].iv_len;
				break;
			}

		if (ctx->cipher_algo == RTE_CRYPTO_CIPHER_LIST_END) {
			RTE_LOG(ERR, DATAPLANE, "Unsupported digest algo %s\n",
				algo_name);
			return -EINVAL;
		}

		if ((!key_len && ctx->cipher_algo != RTE_CRYPTO_CIPHER_NULL) ||
		    key_len > CRYPTO_MAX_KEY_LENGTH) {
			RTE_LOG(ERR, DATAPLANE,
				"Invalid key length %d specified with crypto algorithm %s\n",
				key_len, algo_name);
			return -EINVAL;
		}

		ctx->key_len = key_len;
		memcpy(ctx->key, algo_crypt->alg_key, key_len);
	}

	return 0;
}

static int crypto_rte_set_auth(struct crypto_session *ctx,
			       const struct xfrm_algo_auth *algo_auth)
{
	uint16_t key_len = algo_auth->alg_key_len / BITS_PER_BYTE;
	const char *algo_name = algo_auth->alg_name;

	ctx->auth_algo = RTE_CRYPTO_AUTH_LIST_END;
	for (uint8_t i = 0; i < ARRAY_SIZE(md_algorithms); i++)
		if (!strcmp(md_algorithms[i].name, algo_name)) {
			ctx->md_name = md_algorithms[i].name;
			ctx->auth_algo = md_algorithms[i].auth_algo;
			break;
		}

	if (ctx->auth_algo == RTE_CRYPTO_AUTH_LIST_END) {
		RTE_LOG(ERR, DATAPLANE, "Unsupported digest algo %s\n",
			algo_name);
		return -EINVAL;
	}

	if (!key_len && ctx->auth_algo != RTE_CRYPTO_AUTH_NULL) {
		RTE_LOG(ERR, DATAPLANE,
			"Invalid key size %d specified with auth algo %s\n",
			key_len, algo_name);
		return -EINVAL;
	}

	ctx->auth_alg_key_len = key_len;
	memcpy(ctx->auth_alg_key, algo_auth->alg_key, key_len);
	ctx->digest_len = algo_auth->alg_trunc_len / BITS_PER_BYTE;

	return 0;
}

int crypto_rte_set_session_parameters(struct crypto_session *ctx,
				      const struct xfrm_algo *algo_crypt,
				      const struct xfrm_algo_auth *algo_auth)
{
	int err = 0;

	err = crypto_rte_set_cipher(ctx, algo_crypt);
	if (err)
		return err;

	err = crypto_rte_set_auth(ctx, algo_auth);
	return err;
}

/*
 * select PMD to create based on algorithm requirements
 * Ideally, DPDK should provide an API to query capability based on driver type
 * However, the DPDK API for querying capabilities requires a device to
 * be created first which presents unnecessary overhead.
 * Use a static method of selection for now.
 *
 */
int
crypto_rte_select_pmd_type(enum rte_crypto_cipher_algorithm cipher_algo,
			   enum rte_crypto_aead_algorithm aead_algo,
			   enum cryptodev_type *dev_type, bool *setup_openssl)
{
	if (aead_algo == RTE_CRYPTO_AEAD_AES_GCM) {
		*dev_type = CRYPTODEV_AESNI_GCM;
		*setup_openssl = false;
		return 0;
	}

	switch (cipher_algo) {
	case RTE_CRYPTO_CIPHER_3DES_CBC:
	case RTE_CRYPTO_CIPHER_AES_CBC:
		*dev_type = CRYPTODEV_AESNI_MB;
		*setup_openssl = true;
		break;

	case RTE_CRYPTO_CIPHER_NULL:
		*dev_type = CRYPTODEV_NULL;
		*setup_openssl = true;
		break;

	default:
		return -EINVAL;
	}

	return 0;
}

/*
 * array of dev ids per device type
 * Used as the suffix in the device name
 */
static int8_t pmd_inst_ids[CRYPTODEV_MAX][MAX_CRYPTO_PMD];

static int crypto_rte_find_inst_id(enum cryptodev_type dev_type,
				   int *inst_id)
{
	static int first_time = 1;
	int i;

	if (first_time) {
		memset(pmd_inst_ids, -1, sizeof(pmd_inst_ids));
		first_time = 0;
	}

	for (i = 0; i < MAX_CRYPTO_PMD; i++) {
		if (pmd_inst_ids[dev_type][i] == -1)
			break;
	}

	if (i == MAX_CRYPTO_PMD)
		return -ENOSPC;

	*inst_id = i;
	return 0;
}

int crypto_rte_create_pmd(int cpu_socket, uint8_t dev_id,
			  enum cryptodev_type dev_type, char dev_name[],
			  uint8_t max_name_len, int *rte_dev_id)
{
#define ARGS_LEN     128
	int err;
	char args[ARGS_LEN];
	int inst_id = 0;

	/* look for next available id for this pmd type */
	err = crypto_rte_find_inst_id(dev_type, &inst_id);
	if (err) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not find instance id for dev type %d\n",
			dev_type);
		return err;
	}

	/* create new device */
	snprintf(dev_name, max_name_len, "%s%d", cryptodev_names[dev_type],
		 inst_id);
	snprintf(args, ARGS_LEN, "socket_id=%d", cpu_socket);

	err = rte_vdev_init(dev_name, args);
	if (err != 0) {
		RTE_LOG(ERR, DATAPLANE, "Could not create PMD %s\n",
			dev_name);
		return err;
	}

	*rte_dev_id = rte_cryptodev_get_dev_id(dev_name);
	pmd_inst_ids[dev_type][inst_id] = dev_id;

	return err;
}

/*
 * destroy specified PMD
 */
int crypto_rte_destroy_pmd(enum cryptodev_type dev_type, char dev_name[],
			   int dev_id)
{
	int err, i;

	for (i = 0; i < MAX_CRYPTO_PMD; i++) {
		if (pmd_inst_ids[dev_type][i] == dev_id) {
			pmd_inst_ids[dev_type][i] = -1;
			break;
		}
	}

	if (i == MAX_CRYPTO_PMD) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not find instance id for pmd %s, dev_id %d\n",
			dev_name, dev_id);
		return -EINVAL;
	}

	err = rte_vdev_uninit(dev_name);

	return err;
}
