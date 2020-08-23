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
#define CRYPTO_SESSION_POOL_CACHE_SIZE 512

#define MAX_CRYPTO_OPS 8192
#define CRYPTO_OP_POOL_CACHE_SIZE 256

#define CRYPTO_OP_IV_OFFSET (sizeof(struct rte_crypto_op) + \
			     sizeof(struct rte_crypto_sym_op))

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
		"crypto_session_pool", CRYPTO_MAX_SESSIONS, 0,
		CRYPTO_SESSION_POOL_CACHE_SIZE, 0, socket);
	if (!crypto_session_pool) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not allocate crypto session pool\n");
		return -ENOMEM;
	}

	uint16_t crypto_op_data_size =
		sizeof(struct rte_crypto_sym_op) + CRYPTO_MAX_IV_LENGTH;

	crypto_op_pool = rte_crypto_op_pool_create("crypto_op_pool",
						   RTE_CRYPTO_OP_TYPE_SYMMETRIC,
						   MAX_CRYPTO_OPS,
						   CRYPTO_OP_POOL_CACHE_SIZE,
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
				   CRYPTO_SESSION_POOL_CACHE_SIZE, 0,
				   NULL, NULL, NULL, NULL,
				   socket, 0);
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

int crypto_rte_op_alloc(struct rte_mbuf *m)
{
	struct rte_crypto_op *cop;
	struct pktmbuf_mdata *mdata;

	cop = rte_crypto_op_alloc(crypto_op_pool,
				      RTE_CRYPTO_OP_TYPE_SYMMETRIC);
	if (cop == NULL)
		return -ENOMEM;

	cop->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;
	cop->sess_type = RTE_CRYPTO_OP_WITH_SESSION;
	cop->sym->m_src = m;

	mdata = pktmbuf_mdata(m);
	mdata->cop = cop;
	pktmbuf_mdata_set(m, PKT_MDATA_CRYPTO_OP);

	return 0;
}

void crypto_rte_op_free(struct rte_mbuf *m)
{
	struct rte_crypto_op *cop;
	struct pktmbuf_mdata *mdata;

	mdata = pktmbuf_mdata(m);
	cop = mdata->cop;
	mdata->cop = NULL;
	pktmbuf_mdata_clear(m, PKT_MDATA_CRYPTO_OP);
	rte_crypto_op_free(cop);
}

static int crypto_rte_op_assoc_session(struct rte_crypto_op *cop,
				       struct crypto_session *session)
{
	int err;

	err = rte_crypto_op_attach_sym_session(cop,
					       session->rte_session);
	return err;
}

static int crypto_rte_process_op(uint8_t dev_id, enum crypto_xfrm qid,
				 struct rte_crypto_op *cop)
{
	int rc;

	rc = rte_cryptodev_enqueue_burst(dev_id, qid, &cop, 1);
	if (rc < 1)
		return -ENOSPC;

	do {
		rc = rte_cryptodev_dequeue_burst(dev_id, qid, &cop, 1);
	} while (rc < 1);

	if (cop->status != RTE_CRYPTO_OP_STATUS_SUCCESS)
		rc = -1;
	else
		rc = 0;

	return rc;
}

static inline void
crypto_rte_iv_fill(uint8_t *iv, struct crypto_session *s)
{
	memcpy(iv, s->nonce, s->nonce_len);
	memcpy(iv + s->nonce_len, s->iv, s->iv_len);
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
 * helper function to fill crypto_sym op for aead algorithms
 */
static inline void
crypto_rte_sop_aead_prepare(struct rte_crypto_sym_op *sop,
			    uint32_t l3_hdr_len, uint8_t udp_len,
			    uint32_t esp_len, uint32_t payload_len,
			    uint16_t icv_ofs)
{
	struct rte_mbuf *m = sop->m_src;
	uint16_t esp_start = dp_pktmbuf_l2_len(m) + l3_hdr_len + udp_len;

	sop->aead.data.offset = esp_start + esp_len;
	sop->aead.data.length = payload_len;

	sop->aead.aad.data = rte_pktmbuf_mtod_offset(m, void *, esp_start);
	sop->aead.aad.phys_addr = rte_pktmbuf_iova_offset(m, esp_start);

	sop->aead.digest.data = rte_pktmbuf_mtod_offset(m, void*, icv_ofs);
	sop->aead.digest.phys_addr = rte_pktmbuf_iova_offset(m, icv_ofs);
}

/*
 * setup crypto op and crypto sym op for ESP inbound packet.
 */
static inline int
crypto_rte_inbound_cop_prepare(struct rte_crypto_op *cop,
			       struct crypto_session *session,
			       struct rte_mbuf *m, uint32_t l3_hdr_len,
			       uint8_t udp_len, uint32_t esp_len,
			       unsigned char *iv, uint32_t payload_len)
{
	int err = 0;
	struct rte_crypto_sym_op *sop;
	uint8_t *ivc;
	uint16_t icv_ofs;

	memcpy(session->iv, iv, session->iv_len);
	icv_ofs = rte_pktmbuf_pkt_len(m) - crypto_session_digest_len(session);

	/* fill sym op fields */
	sop = cop->sym;

	if (session->aead_algo == RTE_CRYPTO_AEAD_AES_GCM) {
		crypto_rte_sop_aead_prepare(sop, l3_hdr_len,
					    udp_len, esp_len,
					    payload_len, icv_ofs);

		/* fill AAD IV (located inside crypto op) */
		ivc = rte_crypto_op_ctod_offset(cop, uint8_t *,
					       CRYPTO_OP_IV_OFFSET);
		crypto_rte_iv_fill(ivc, session);
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
		crypto_rte_iv_fill(ivc, session);
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
				uint32_t payload_len)
{
	int err = 0;
	struct rte_crypto_sym_op *sop;
	uint8_t *ivc;
	uint16_t icv_ofs;

	icv_ofs = dp_pktmbuf_l2_len(m) + l3_hdr_len + udp_len + esp_len +
		payload_len;

	/* fill sym op fields */
	sop = cop->sym;

	if (session->aead_algo == RTE_CRYPTO_AEAD_AES_GCM) {
		crypto_rte_sop_aead_prepare(sop, l3_hdr_len, udp_len,
					    esp_len, payload_len,
					    icv_ofs);

		/* fill AAD IV (located inside crypto op) */
		ivc = rte_crypto_op_ctod_offset(cop, uint8_t *,
						CRYPTO_OP_IV_OFFSET);
		crypto_rte_iv_fill(ivc, session);
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
		crypto_rte_iv_fill(ivc, session);
		break;

	case RTE_CRYPTO_CIPHER_NULL:
		break;

	default:
		err = -EINVAL;
	}

	return err;
}

int crypto_rte_xform_packet(struct sadb_sa *sa, struct rte_mbuf *mbuf,
			    unsigned int l3_hdr_len, unsigned char *esp,
			    unsigned char *iv, uint32_t text_len,
			    uint32_t esp_len, uint8_t encrypt)
{
	int err;
	struct rte_crypto_op *cop;
	struct pktmbuf_mdata *mdata;
	uint8_t udp_len = 0;
	struct crypto_session *session = sa->session;
	enum crypto_xfrm qid;

	if (unlikely(mbuf->next)) {
		if (sa->session->cipher_init) {
			err = esp_generate_chain(sa, mbuf, l3_hdr_len, esp, iv,
						text_len + esp_len, encrypt);
			return err;
		}
	}

	mdata = pktmbuf_mdata(mbuf);
	cop = mdata->cop;
	err = crypto_rte_op_assoc_session(cop, session);
	if (err)
		return err;

	if (sa->udp_encap)
		udp_len = sizeof(struct udphdr);

	if (encrypt)
		err = crypto_rte_outbound_cop_prepare(cop, session, mbuf,
						      l3_hdr_len, udp_len,
						      esp_len, text_len);
	else
		err = crypto_rte_inbound_cop_prepare(cop, session, mbuf,
						     l3_hdr_len, udp_len,
						     esp_len, iv, text_len);

	if (err)
		return err;

	qid = sa->dir == CRYPTO_DIR_IN ? CRYPTO_DECRYPT : CRYPTO_ENCRYPT;
	err = crypto_rte_process_op(sa->rte_cdev_id, qid, cop);

	return err;
}
