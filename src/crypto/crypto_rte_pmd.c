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
#include "esp.h"

/*
 * Support for 16K sessions ( = 8K tunnels )
 */
#define CRYPTO_MAX_SESSIONS (1 << 14)

#define CRYPTO_OP_CTX_OFFSET (sizeof(struct rte_crypto_op) + \
			      sizeof(struct rte_crypto_sym_op))

#define CRYPTO_OP_IV_OFFSET (CRYPTO_OP_CTX_OFFSET + \
			     sizeof(struct crypto_pkt_ctx **))

/* per session (SA) data structure used to set up operations with PMDs */
static struct rte_mempool *crypto_session_pool;

/* per session data structure for private driver data */
static struct rte_mempool *crypto_priv_sess_pools[CRYPTODEV_MAX];

static uint8_t dev_cnts[CRYPTODEV_MAX];

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
		"crypto_session_pool", CRYPTO_MAX_SESSIONS, 0, 0, 0, socket);
	if (!crypto_session_pool) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not allocate crypto session pool\n");
		return -ENOMEM;
	}

	uint16_t crypto_op_data_size =
		sizeof(struct rte_crypto_sym_op) +
		sizeof(struct crypto_pkt_ctx **) + CRYPTO_MAX_IV_LENGTH;

	/*
	 * dp_lcore_events_init gets invoked from the main thread as well
	 * and leads to a UT failure if the pool is not sized to take that
	 * into account
	 */
	uint16_t crypto_op_pool_size =
		MAX_CRYPTO_PKT_BURST * (rte_lcore_count() + 1);

	crypto_op_pool = rte_crypto_op_pool_create("crypto_op_pool",
						   RTE_CRYPTO_OP_TYPE_SYMMETRIC,
						   crypto_op_pool_size, 0,
						   crypto_op_data_size,
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

struct cipher_algo_table {
	const char *name;
	enum rte_crypto_cipher_algorithm cipher_algo;
	uint8_t iv_len;
	uint8_t block_size;
};

#define AES_BLOCK_SIZE 16
#define DES3_BLOCK_SIZE 8

/* AES-GCM does not have padding requirements */
#define AES_GCM_BLOCK_SIZE 1

static const struct cipher_algo_table cipher_algorithms[] = {
	{ "cbc(aes)",         RTE_CRYPTO_CIPHER_AES_CBC,
	  IPSEC_AES_CBC_IV_SIZE,  AES_BLOCK_SIZE  },
	{ "cbc(des3_ede)",    RTE_CRYPTO_CIPHER_3DES_CBC,
	  IPSEC_3DES_IV_SIZE,     DES3_BLOCK_SIZE },
	{ "eNULL",            RTE_CRYPTO_CIPHER_NULL,
	  0,                      1               },
	{ "ecb(cipher_null)", RTE_CRYPTO_CIPHER_NULL,
	  0,                      1               }
};

struct md_algo_table {
	const char *name;
	enum rte_crypto_auth_algorithm auth_algo;
};

static const struct md_algo_table md_algorithms[] = {
	{ "hmac(sha1)",		RTE_CRYPTO_AUTH_SHA1_HMAC    },
	{ "hmac(sha256)",	RTE_CRYPTO_AUTH_SHA256_HMAC  },
	{ "hmac(sha384)",	RTE_CRYPTO_AUTH_SHA384_HMAC  },
	{ "hmac(sha512)",	RTE_CRYPTO_AUTH_SHA512_HMAC  },
	{ "hmac(md5)",		RTE_CRYPTO_AUTH_MD5_HMAC     },
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
	ctx->block_size = AES_GCM_BLOCK_SIZE;

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
	ctx->aead_algo = RTE_CRYPTO_AEAD_LIST_END;
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
				ctx->block_size =
					cipher_algorithms[i].block_size;
				break;
			}

		if (ctx->cipher_algo == RTE_CRYPTO_CIPHER_LIST_END) {
			RTE_LOG(ERR, DATAPLANE, "Unsupported digest algo %s\n",
				algo_name);
			return -EINVAL;
		}

		if ((!key_len && ctx->cipher_algo != RTE_CRYPTO_CIPHER_NULL) ||
		    key_len > CRYPTO_MAX_CIPHER_KEY_LENGTH) {
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
			ctx->auth_algo = md_algorithms[i].auth_algo;
			break;
		}

	if (ctx->auth_algo == RTE_CRYPTO_AUTH_LIST_END) {
		RTE_LOG(ERR, DATAPLANE, "Unsupported digest algo %s\n",
			algo_name);
		return -EINVAL;
	}

	if ((!key_len && ctx->auth_algo != RTE_CRYPTO_AUTH_NULL) ||
	    key_len > CRYPTO_MAX_AUTH_KEY_LENGTH) {
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
		RTE_LOG(ERR, CRYPTO, "Invalid cipher %d requested\n",
			cipher_algo);
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

static int crypto_rte_setup_priv_pool(enum cryptodev_type dev_type,
				      unsigned int session_size)
{
#define POOL_NAME_LEN 50
	char pool_name[POOL_NAME_LEN];
	unsigned int socket = rte_lcore_to_socket_id(rte_get_master_lcore());

	snprintf(pool_name, POOL_NAME_LEN, "crypto_sess_priv_pool_%d",
		 dev_type);
	crypto_priv_sess_pools[dev_type] =
		rte_mempool_create(pool_name, CRYPTO_MAX_SESSIONS, session_size,
				   0, 0, NULL, NULL, NULL, NULL, socket, 0);
	if (!crypto_priv_sess_pools[dev_type]) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not allocate crypto session private pool for socket %d, dev %s\n",
			socket, cryptodev_names[dev_type]);
		return -ENOMEM;
	}
	return 0;
}

static void crypto_rte_destroy_priv_pool(enum cryptodev_type dev_type)
{
	if (crypto_priv_sess_pools[dev_type]) {
		rte_mempool_free(crypto_priv_sess_pools[dev_type]);
		crypto_priv_sess_pools[dev_type] = NULL;
	}
}

int crypto_rte_create_pmd(int cpu_socket, uint8_t dev_id,
			  enum cryptodev_type dev_type, char dev_name[],
			  uint8_t max_name_len, int *rte_dev_id)
{
#define ARGS_LEN     128
	int err;
	char args[ARGS_LEN];
	int inst_id = 0;
	unsigned int session_size;
	struct rte_cryptodev_config conf = {
		.nb_queue_pairs = MAX_CRYPTO_XFRM,
		.socket_id = cpu_socket
	};

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

	session_size =
		rte_cryptodev_sym_get_private_session_size(*rte_dev_id);

	if (!crypto_priv_sess_pools[dev_type]) {
		err = crypto_rte_setup_priv_pool(dev_type, session_size);
		if (err)
			goto fail;
	}

	err = rte_cryptodev_configure(*rte_dev_id, &conf);
	if (err != 0) {
		RTE_LOG(ERR, DATAPLANE,
			"Failed to configure crypto device %s : %s\n",
			dev_name, strerror(-err));
		goto fail;
	}

	struct rte_cryptodev_qp_conf qp_conf = {
		.nb_descriptors = 2048,
		.mp_session = crypto_session_pool,
		.mp_session_private = crypto_priv_sess_pools[dev_type]
	};

	for (int i = MIN_CRYPTO_XFRM; i < MAX_CRYPTO_XFRM; i++) {
		err = rte_cryptodev_queue_pair_setup(*rte_dev_id, i,
						     &qp_conf,
						     cpu_socket);
		if (err != 0) {
			RTE_LOG(ERR, DATAPLANE,
				"Failed to set up queue pair %d for crypto device %s : %s\n",
				i, dev_name, strerror(err));
			goto fail;
		}
	}

	err = rte_cryptodev_start(*rte_dev_id);
	if (err != 0) {
		RTE_LOG(ERR, DATAPLANE,
			"Failed to start crypto device %s\n", dev_name);
		goto fail;
	}

	pmd_inst_ids[dev_type][inst_id] = dev_id;
	dev_cnts[dev_type]++;

	return err;

fail:
	if (!dev_cnts[dev_type])
		crypto_rte_destroy_priv_pool(dev_type);
	rte_vdev_uninit(dev_name);
	return err;
}

/*
 * destroy specified PMD
 */
int crypto_rte_destroy_pmd(enum cryptodev_type dev_type, char dev_name[],
			   int dev_id)
{
	int err = 0, i, rte_dev_id;

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

	rte_dev_id = rte_cryptodev_get_dev_id(dev_name);
	if (rte_dev_id < 0) {
		RTE_LOG(ERR, DATAPLANE, "Could not find id for device %s\n",
			dev_name);
		return -ENOENT;
	}

	rte_cryptodev_stop(rte_dev_id);

	err = rte_vdev_uninit(dev_name);
	if (err) {
		RTE_LOG(ERR, DATAPLANE, "Could not uninit device %s\n",
			dev_name);
		return err;
	}

	dev_cnts[dev_type]--;
	if (!dev_cnts[dev_type])
		crypto_rte_destroy_priv_pool(dev_type);

	return err;
}

static void
crypto_rte_setup_xform_chain(struct crypto_session *session,
			     struct rte_crypto_sym_xform *cipher_xform,
			     struct rte_crypto_sym_xform *auth_xform,
			     struct rte_crypto_sym_xform **xform_chain)
{
	int direction = session->direction;
	static enum rte_crypto_cipher_operation cipher_ops[2] = {
		[XFRM_POLICY_OUT] = RTE_CRYPTO_CIPHER_OP_ENCRYPT,
		[XFRM_POLICY_IN] = RTE_CRYPTO_CIPHER_OP_DECRYPT
	};
	static enum rte_crypto_auth_operation auth_ops[2] = {
		[XFRM_POLICY_OUT] = RTE_CRYPTO_AUTH_OP_GENERATE,
		[XFRM_POLICY_IN] = RTE_CRYPTO_AUTH_OP_VERIFY
	};
	static enum rte_crypto_aead_operation aead_ops[2] = {
		[XFRM_POLICY_OUT] = RTE_CRYPTO_AEAD_OP_ENCRYPT,
		[XFRM_POLICY_IN] = RTE_CRYPTO_AEAD_OP_DECRYPT
	};

	if (session->aead_algo == RTE_CRYPTO_AEAD_AES_GCM) {
		cipher_xform->type = RTE_CRYPTO_SYM_XFORM_AEAD;
		cipher_xform->aead.op = aead_ops[direction];
		cipher_xform->aead.algo = session->aead_algo;
		cipher_xform->aead.aad_length = 8; /* no ESN support yet */
		cipher_xform->aead.iv.offset = CRYPTO_OP_IV_OFFSET;
		cipher_xform->aead.iv.length =
			session->iv_len + session->nonce_len;
		cipher_xform->aead.key.data = session->key;
		cipher_xform->aead.key.length = session->key_len;
		cipher_xform->aead.digest_length = session->digest_len;
		cipher_xform->next = NULL;
		*xform_chain = cipher_xform;
	} else {
		/* set up data for cipher */
		cipher_xform->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
		cipher_xform->cipher.op = cipher_ops[direction];
		cipher_xform->cipher.algo = session->cipher_algo;
		cipher_xform->cipher.key.data = session->key;
		cipher_xform->cipher.key.length = session->key_len;
		cipher_xform->cipher.iv.length =
			session->iv_len + session->nonce_len;
		cipher_xform->cipher.iv.offset = CRYPTO_OP_IV_OFFSET;

		/* set up data for authentication */
		auth_xform->type = RTE_CRYPTO_SYM_XFORM_AUTH;
		auth_xform->auth.op = auth_ops[direction];
		auth_xform->auth.algo = session->auth_algo;
		auth_xform->auth.key.data =
			(const uint8_t *)session->auth_alg_key;
		auth_xform->auth.key.length = session->auth_alg_key_len;
		auth_xform->auth.digest_length = session->digest_len;

		/* set up transform chain */
		if (direction == XFRM_POLICY_IN) {
			auth_xform->next = cipher_xform;
			cipher_xform->next = NULL;
			*xform_chain = auth_xform;
		} else {
			cipher_xform->next = auth_xform;
			auth_xform->next = NULL;
			*xform_chain = cipher_xform;
		}
	}
}

int crypto_rte_setup_session(struct crypto_session *session,
			     enum cryptodev_type dev_type, uint8_t rte_cdev_id)
{
	struct rte_crypto_sym_xform cipher_xform, auth_xform, *xform_chain;
	int err = 0;

	crypto_rte_setup_xform_chain(session, &cipher_xform, &auth_xform,
				     &xform_chain);

	session->rte_session =
		rte_cryptodev_sym_session_create(crypto_session_pool);
	if (!session->rte_session) {
		RTE_LOG(ERR, DATAPLANE, "Could not create cryptodev session\n");
		return -ENOMEM;
	}

	err = rte_cryptodev_sym_session_init(
		rte_cdev_id, session->rte_session, xform_chain,
		crypto_priv_sess_pools[dev_type]);
	if (err) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not initialize cryptodev session\n");
		rte_cryptodev_sym_session_free(session->rte_session);
		session->rte_session = NULL;
	}

	return err;
}

int crypto_rte_destroy_session(struct crypto_session *session,
			       uint8_t rte_cdev_id)
{
	int err;

	if (!session->rte_session)
		return 0;

	rte_cryptodev_sym_session_clear(rte_cdev_id, session->rte_session);
	err = rte_cryptodev_sym_session_free(session->rte_session);
	if (err) {
		RTE_LOG(ERR, DATAPLANE,
			"Failed to free cryptodev session : %s\n",
			strerror(-err));
		return err;
	}

	session->rte_session = NULL;
	return err;
}

int crypto_rte_op_alloc(struct rte_crypto_op *cops[], uint16_t count)
{
	uint16_t i;

	if (rte_crypto_op_bulk_alloc(crypto_op_pool,
				     RTE_CRYPTO_OP_TYPE_SYMMETRIC,
				     cops, count) != count)
		return -ENOMEM;

	for (i = 0; i < count; i++)
		cops[i]->sess_type = RTE_CRYPTO_OP_WITH_SESSION;

	return 0;
}

void crypto_rte_op_free(struct rte_crypto_op *cops[], uint16_t count)
{
	for (uint16_t i = 0; i < count; i++)
		rte_crypto_op_free(cops[i]);
}

static inline int
crypto_rte_op_assoc_session(struct rte_crypto_op *cop,
			    struct crypto_session *session)
{
	int err;

	cop->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;
	err = rte_crypto_op_attach_sym_session(cop,
					       session->rte_session);
	return err;
}

struct crypto_rte_pkt_batch {
	uint8_t cdev_id;
	uint16_t batch_size;
	enum crypto_xfrm qid;
	struct rte_crypto_op *cop_arr[MAX_CRYPTO_PKT_BURST];
};

static inline
void crypto_rte_process_op_batch(struct crypto_rte_pkt_batch *batch)
{
	uint8_t enqueued = 0, dequeued = 0, tmp_cnt;
	struct crypto_pkt_ctx *ctx;
	struct rte_crypto_op *cop;

	while (dequeued < batch->batch_size) {
		tmp_cnt = rte_cryptodev_enqueue_burst(
			batch->cdev_id, batch->qid,
			&batch->cop_arr[enqueued],
			batch->batch_size - enqueued);
		enqueued += tmp_cnt;

		tmp_cnt = rte_cryptodev_dequeue_burst(
			batch->cdev_id, batch->qid,
			&batch->cop_arr[dequeued],
			batch->batch_size - dequeued);
		dequeued += tmp_cnt;

		if (!tmp_cnt)
			break;
	}

	if (unlikely(dequeued < batch->batch_size))
		IPSEC_CNT_INC_BY(CRYPTO_OP_FAILED,
				 (batch->batch_size - dequeued));

	for (tmp_cnt = 0; tmp_cnt < dequeued; tmp_cnt++) {
		cop = batch->cop_arr[tmp_cnt];
		if (likely(cop->status ==
			   RTE_CRYPTO_OP_STATUS_SUCCESS)) {

			ctx = *(rte_crypto_op_ctod_offset(
					cop,
					struct crypto_pkt_ctx **,
					CRYPTO_OP_CTX_OFFSET));
			ctx->status = 0;
		} else
			IPSEC_CNT_INC(CRYPTO_OP_FAILED);
	}
	batch->batch_size = 0;
}

static inline void
crypto_rte_iv_fill(uint8_t *iv, struct crypto_session *s,
		   char *cur_iv)
{
	memcpy(iv, s->nonce, s->nonce_len);
	memcpy(iv + s->nonce_len, cur_iv, s->iv_len);
}

static inline void
crypto_rte_sop_ciph_auth_prepare(struct rte_crypto_sym_op *sop,
				 uint32_t l3_hdr_len, uint8_t udp_len,
				 uint32_t esp_len, uint32_t payload_len,
				 uint16_t icv_ofs)
{
	struct rte_mbuf *m = sop->m_src;
	uint16_t esp_start = dp_pktmbuf_l2_len(m) + l3_hdr_len + udp_len;

	sop->cipher.data.offset = esp_start + esp_len;
	sop->cipher.data.length = payload_len;

	sop->auth.data.offset = esp_start;
	sop->auth.data.length = esp_len + payload_len;

	sop->auth.digest.data = rte_pktmbuf_mtod_offset(m, void*, icv_ofs);
	sop->auth.digest.phys_addr = rte_pktmbuf_iova_offset(m, icv_ofs);
}

/*
 * adjust last segment if necessary to hold the entire ICV
 */
static inline void
crypto_rte_fixup_icv(struct rte_mbuf *m, uint16_t icv_len)
{
	struct rte_mbuf *p_mbuf, *l_mbuf;
	uint8_t icv[icv_len], *data;
	uint16_t icv1_len, icv2_len, icv_ofs;

	p_mbuf = NULL;
	l_mbuf = m;
	while (l_mbuf->next != NULL) {
		p_mbuf = l_mbuf;
		l_mbuf = l_mbuf->next;
	}

	if (l_mbuf->data_len >= icv_len)
		return;

	icv2_len = icv_len - l_mbuf->data_len;
	icv1_len = icv_len - icv2_len;
	icv_ofs = p_mbuf->data_len - icv1_len;
	data = rte_pktmbuf_mtod_offset(p_mbuf, uint8_t *, icv_ofs);
	memcpy(icv, data, icv1_len);
	data = rte_pktmbuf_mtod(l_mbuf, uint8_t *);
	memcpy(&icv[icv1_len], data, icv2_len);
	memcpy(data, icv, icv_len);
	l_mbuf->data_len += icv1_len;
	l_mbuf->pkt_len += icv1_len;
	p_mbuf->data_len -= icv1_len;
	p_mbuf->pkt_len -= icv1_len;
}


/*
 * helper function to fill crypto_sym op for aead algorithms
 */
static inline void
crypto_rte_sop_aead_prepare(struct rte_crypto_sym_op *sop,
			    uint32_t l3_hdr_len, uint8_t udp_len,
			    uint32_t esp_len, uint32_t payload_len,
			    uint16_t icv_len, bool encrypt)
{
	struct rte_mbuf *m = sop->m_src, *last_seg = m;
	uint16_t esp_start = dp_pktmbuf_l2_len(m) + l3_hdr_len + udp_len;
	uint16_t icv_ofs;

	sop->aead.data.offset = esp_start + esp_len;
	sop->aead.data.length = payload_len;

	sop->aead.aad.data = rte_pktmbuf_mtod_offset(m, void *, esp_start);
	sop->aead.aad.phys_addr = rte_pktmbuf_iova_offset(m, esp_start);

	if (unlikely(m->nb_segs > 1)) {
		if (!encrypt)
			crypto_rte_fixup_icv(m, icv_len);

		last_seg = rte_pktmbuf_lastseg(m);
	}
	icv_ofs = last_seg->data_len - icv_len;
	sop->aead.digest.data = rte_pktmbuf_mtod_offset(last_seg, void *,
							icv_ofs);
	sop->aead.digest.phys_addr =
		rte_pktmbuf_iova_offset(last_seg, icv_ofs);
}

/*
 * setup crypto op and crypto sym op for ESP inbound packet.
 */
static inline int
crypto_rte_inbound_cop_prepare(struct rte_crypto_op *cop,
			       struct crypto_session *session,
			       struct rte_mbuf *m, uint32_t l3_hdr_len,
			       uint8_t udp_len, uint32_t esp_len,
			       char *iv, uint32_t payload_len)
{
	int err = 0;
	struct rte_crypto_sym_op *sop;
	uint8_t *ivc;
	uint16_t icv_ofs, icv_len;

	memcpy(session->iv, iv, session->iv_len);
	icv_len = crypto_session_digest_len(session);
	icv_ofs = rte_pktmbuf_pkt_len(m) - icv_len;

	/* fill sym op fields */
	sop = cop->sym;

	if (session->aead_algo == RTE_CRYPTO_AEAD_AES_GCM) {
		crypto_rte_sop_aead_prepare(sop, l3_hdr_len,
					    udp_len, esp_len,
					    payload_len, icv_len, false);

		/* fill AAD IV (located inside crypto op) */
		ivc = rte_crypto_op_ctod_offset(cop, uint8_t *,
					       CRYPTO_OP_IV_OFFSET);
		crypto_rte_iv_fill(ivc, session, iv);
		return err;
	}

	switch (session->cipher_algo) {
	case RTE_CRYPTO_CIPHER_AES_CBC:
	case RTE_CRYPTO_CIPHER_3DES_CBC:
		crypto_rte_sop_ciph_auth_prepare(sop, l3_hdr_len,
						 udp_len, esp_len,
						 payload_len, icv_ofs);

		/* copy iv from the input packet to the cop */
		ivc = rte_crypto_op_ctod_offset(
			cop, uint8_t *, CRYPTO_OP_IV_OFFSET);
		crypto_rte_iv_fill(ivc, session, iv);
		break;
	case RTE_CRYPTO_CIPHER_NULL:
		break;

	default:
		err = -EINVAL;
	}

	return err;
}

/*
 * setup crypto op and crypto sym op for ESP outbound packet.
 */
static inline int
crypto_rte_outbound_cop_prepare(struct rte_crypto_op *cop,
				struct crypto_session *session,
				struct rte_mbuf *m, uint32_t l3_hdr_len,
				uint8_t udp_len, uint32_t esp_len,
				char *iv, uint32_t payload_len)
{
	int err = 0;
	struct rte_crypto_sym_op *sop;
	uint8_t *ivc;
	uint16_t icv_ofs, icv_len;

	icv_ofs = dp_pktmbuf_l2_len(m) + l3_hdr_len + udp_len + esp_len +
		payload_len;
	icv_len = crypto_session_digest_len(session);

	/* fill sym op fields */
	sop = cop->sym;

	if (session->aead_algo == RTE_CRYPTO_AEAD_AES_GCM) {
		crypto_rte_sop_aead_prepare(sop, l3_hdr_len, udp_len,
					    esp_len, payload_len,
					    icv_len, true);

		/* fill AAD IV (located inside crypto op) */
		ivc = rte_crypto_op_ctod_offset(cop, uint8_t *,
						CRYPTO_OP_IV_OFFSET);
		crypto_rte_iv_fill(ivc, session, iv);
		return err;
	}

	switch (session->cipher_algo) {
	case RTE_CRYPTO_CIPHER_AES_CBC:
	case RTE_CRYPTO_CIPHER_3DES_CBC:
		crypto_rte_sop_ciph_auth_prepare(sop, l3_hdr_len,
						 udp_len, esp_len,
						 payload_len,
						 icv_ofs);

		/* copy iv from the input packet to the cop */
		ivc = rte_crypto_op_ctod_offset(
			cop, uint8_t *, CRYPTO_OP_IV_OFFSET);
		crypto_rte_iv_fill(ivc, session, iv);
		break;

	case RTE_CRYPTO_CIPHER_NULL:
		break;

	default:
		err = -EINVAL;
	}

	return err;
}

inline __attribute__((always_inline)) uint16_t
crypto_rte_xform_packets(struct crypto_pkt_ctx *cctx_arr[], uint16_t count)
{
	int err;
	struct crypto_session *session;
	enum crypto_xfrm qid;
	uint16_t i, text_len, hdr_len;
	struct crypto_rte_pkt_batch pkt_batch;
	struct crypto_pkt_ctx *cctx, **ctx_ptr;
	bool encrypt;
	struct rte_crypto_op *cop;
	struct crypto_pkt_buffer *cpb = cpbdb[dp_lcore_id()];
	uint16_t bad_idx[count], bad_cnt = 0;

	pkt_batch.cdev_id = 0;
	pkt_batch.qid = 0;
	pkt_batch.batch_size = 0;

	assert(count <= MAX_CRYPTO_PKT_BURST);

	for (i = 0; i < count; i++) {
		crypto_prefetch_ctx(cctx_arr, count, i);

		crypto_prefetch_ops(i, count);

		cctx = cctx_arr[i];
		session = cctx->sa->session;
		encrypt = (cctx->sa->dir == CRYPTO_DIR_OUT);

		if (unlikely(cctx->mbuf->next && session->cipher_init)) {
			crypto_rte_process_op_batch(&pkt_batch);
			hdr_len = encrypt ? cctx->out_hdr_len : cctx->iphlen;
			text_len = encrypt ? cctx->plaintext_size :
				cctx->ciphertext_len;
			err = esp_generate_chain(cctx->sa, cctx->mbuf,
						 hdr_len, cctx->esp, cctx->iv,
						 text_len + cctx->esp_len,
						 encrypt);
			if (err)
				cctx_arr[i]->status = -1;
			continue;
		}

		cop = cpb->cops[i];

		err = crypto_rte_op_assoc_session(cop, session);
		if (unlikely(err)) {
			cctx->status = -1;
			IPSEC_CNT_INC(CRYPTO_OP_ASSOC_FAILED);
			continue;
		}
		cop->sym->m_src = cctx->mbuf;
		if (encrypt) {
			err = crypto_rte_outbound_cop_prepare(
				cop, session, cctx->mbuf,
				cctx->out_hdr_len,
				cctx->sa->udp_encap, cctx->esp_len,
				(char *)cctx->iv, cctx->plaintext_size);
			qid = CRYPTO_ENCRYPT;
		} else {
			err = crypto_rte_inbound_cop_prepare(
				cop, session, cctx->mbuf, cctx->iphlen,
				cctx->sa->udp_encap, cctx->esp_len,
				(char *)cctx->iv, cctx->ciphertext_len);
			qid = CRYPTO_DECRYPT;
		}
		if (unlikely(err)) {
			cctx->status = -1;
			IPSEC_CNT_INC(CRYPTO_OP_PREPARE_FAILED);
			continue;
		}

		/*
		 * Explicitly set status to failure for each packet
		 * being handed to the PMD. The status will be set to 0
		 * again after successful processing. This allows us to handle
		 * any cases of mismatch between enqueue and dequeue
		 */
		cctx->status = -1;
		ctx_ptr = rte_crypto_op_ctod_offset(cop,
						    struct crypto_pkt_ctx **,
						    CRYPTO_OP_CTX_OFFSET);
		*ctx_ptr = cctx;

		crypto_prefetch_ctx_data(cctx_arr, count, i);

		if (pkt_batch.cdev_id != cctx->sa->rte_cdev_id ||
		    pkt_batch.qid != qid) {
			crypto_rte_process_op_batch(&pkt_batch);
			pkt_batch.cdev_id = cctx->sa->rte_cdev_id;
			pkt_batch.qid = qid;
		}
		pkt_batch.cop_arr[pkt_batch.batch_size] = cop;
		pkt_batch.batch_size++;
	}
	crypto_rte_process_op_batch(&pkt_batch);
	for (i = 0; i < count; i++)
		if (cctx_arr[i]->status < 0)
			bad_idx[bad_cnt++] = i;
	move_bad_mbufs(cctx_arr, count, bad_idx, bad_cnt);
	return count - bad_cnt;
}
