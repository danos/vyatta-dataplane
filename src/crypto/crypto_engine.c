/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <linux/xfrm.h> // conflicts with netinet/in.h
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ossl_typ.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_crypto_sym.h>
#include <rte_log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "../in_cksum.h"
#include "compiler.h"
#include "crypto_internal.h"
#include "in6.h"
#include "json_writer.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "crypto_rte_pmd.h"

#define ENGINE_DEBUG(args...)				\
	DP_DEBUG(CRYPTO, DEBUG, ENGINE, args)

#define ENGINE_PKT_ERR(args...)				\
	DP_DEBUG(CRYPTO, NOTICE, ENGINE, args)

#define ENGINE_ERR(args...)				\
	DP_DEBUG(CRYPTO, ERR, ENGINE, args)

#define ENGINE_INFO(args...)				\
	DP_DEBUG(CRYPTO, INFO, ENGINE, args)

typedef EVP_MD * (*evp_md_fn_t)(void);

struct md_algo_table {
	const char *name;
	evp_md_fn_t fn;
};

static const struct md_algo_table md_algorithms[] = {
	{ "hmac(sha1)",		(evp_md_fn_t)EVP_sha1},
	{ "hmac(sha256)",	(evp_md_fn_t)EVP_sha256},
	{ "hmac(sha384)",	(evp_md_fn_t)EVP_sha384},
	{ "hmac(sha512)",	(evp_md_fn_t)EVP_sha512},
	{ "hmac(md5)",		(evp_md_fn_t)EVP_md5},
	{ "rfc4106(gcm(aes))",  (evp_md_fn_t)EVP_md_null},
	{ "aNULL",		(evp_md_fn_t)EVP_md_null},
};

const char *eng_cmd_str[] = {"ENG_CIPHER_INIT |", "ENG_DIGEST_INIT |",
			     "ENG_CIPHER_BLOCK |", "ENG_DIGEST_BLOCK |",
			     "ENG_CIPHER_FINALISE |", "ENG_DIGEST_FINALISE |",
			     "ENG_DIGEST_VERIFY"};

#define ENG_CMD_STR_BUF_SIZE 128

static unsigned int
crypto_engine_cmd2str(int cmd, char *buffer, unsigned int buflen)
{
	int total = 0, pos, str_pos;

	if (buflen < ENG_CMD_STR_BUF_SIZE) {
		ENGINE_ERR("empty buffer supplied\n");
		return 0;
	}

	for (pos = ENG_CIPHER_INIT, str_pos = 0; pos < ENG_CMD_MAX;
	     pos = pos << 1) {
		if (cmd & pos) {
			if ((buflen - (total + 1)) >=
			    strlen(eng_cmd_str[str_pos])) {
				total += snprintf(buffer + total,
						  buflen - total,
						  "%s",
						  eng_cmd_str[str_pos]);
				cmd &= ~pos;
			} else {
				ENGINE_ERR("Eng cmd buffer full %d %d\n",
					   cmd, buflen);
				return 0;
			}
		}
		str_pos++;
	}

	if (cmd)
		ENGINE_ERR("Unexpected leftover bits in flag %d\n", cmd);

	return total;
}

static uint32_t dump_byte_mem(char *buffer,
			      uint32_t  buffer_size,
			      const unsigned char *memory,
			      uint32_t mem_size)
{
	uint32_t i,  len = 0, offset = 0;
	const unsigned char *ptr = memory;

	for (i = 0; i < mem_size; i++, ptr++) {
		len  = snprintf(buffer + offset, buffer_size - offset,
				"%2.2X ", *ptr);
		offset = offset + len;
	}
	*(buffer + offset) = '\0';
	return offset;
}

static void dump_data(const unsigned char *memory, uint32_t memsize)
{
	const unsigned char *ptr = memory;
	uint32_t i;
	char print_buffer[258];

	for (i = 0; i < (memsize / 16); i++, ptr += 16)	{
		dump_byte_mem(print_buffer, 256, ptr, 16);
		ENGINE_DEBUG("%4d: %s\n", i<<4, print_buffer);
	}

	if (memsize % 16) {
		dump_byte_mem(print_buffer, 256, ptr, memsize % 16);
		ENGINE_DEBUG("%4d: %s\n", i<<4, print_buffer);
	}
}

/*
 * Call this function instead of OpenSSL's ERR_print_errors() to output the
 * errors strings for all errors that OpenSSL has recorded to the error queue.
 */
static void ENGINE_ERR_print_errors(void)
{
	BIO *bio = BIO_new(BIO_s_mem());
	char *buf = NULL;
	int len;

	ERR_print_errors(bio);
	len = BIO_get_mem_data(bio, &buf);
	ENGINE_ERR("EVP error(%ld): %.*s\n", ERR_peek_last_error(), len, buf);
	BIO_free_all(bio);
}

static int hmac_update(struct crypto_session *sa,
		       unsigned char *text, uint32_t len)
{
	if (!HMAC_Update(sa->hmac_ctx, text, len)) {
		ENGINE_ERR("HMAC update failed\n");
		return -1;
	}
	return 0;
}

#define ctx_session(ctx) ((ctx)->session)

static int openssl_cipher_set_iv(struct crypto_visitor_ctx *ctx,
				 unsigned int length,
				 const unsigned char iv[])
{
	struct crypto_session *s = ctx_session(ctx);
	unsigned char alg_iv[EVP_MAX_IV_LENGTH];

	if (length < s->iv_len) {
		ENGINE_PKT_ERR("IV too short\n");
		return -1;
	}

	memcpy(alg_iv, s->nonce, s->nonce_len);
	memcpy(alg_iv + s->nonce_len, iv, s->iv_len);

	if (EVP_CipherInit_ex(s->ctx, NULL, NULL, NULL, alg_iv, -1) != 1) {
		ENGINE_ERR_print_errors();
		return -1;
	}

	return 0;
}

static int openssl_hmac_set_icv(struct crypto_visitor_ctx *ctx,
				unsigned int length __rte_unused,
				unsigned char icv[] __rte_unused)
{
	struct crypto_session *session = ctx_session(ctx);

	if (!HMAC_Init_ex(session->hmac_ctx, NULL, 0, NULL, NULL)) {
		ENGINE_ERR("HMAC init failed\n");
		return -1;
	}

	return 0;
}

static int openssl_encrypt_hmac_payload_block(
	struct crypto_visitor_ctx *ctx,
	struct crypto_chain_elem *element)
{
	struct crypto_session *session = ctx_session(ctx);
	int len;

	if (EVP_EncryptUpdate(session->ctx, element->o_data, &len,
			      element->i_data, element->data_len) != 1) {
		ENGINE_ERR_print_errors();
		return -1;
	}

	/*
	 * As this is encrypt we need to run the hmac  operation on the data
	 * after it is encrypted.
	 */
	if (element->flags & ENG_DIGEST_BLOCK) {
		if (hmac_update(session, element->o_data,
				element->data_len) < 0)
			return -1;
	}

	return 0;
}

static int openssl_hmac_decrypt_payload_block(
	struct crypto_visitor_ctx *ctx,
	struct crypto_chain_elem *element)
{
	struct crypto_session *s = ctx_session(ctx);
	int len;

	/*
	 * As this is decrypt we need to run the hmac operation on the data
	 * before it is decrypted.
	 */
	if (element->flags & ENG_DIGEST_BLOCK) {
		if (hmac_update(s, element->i_data, element->data_len) < 0)
			return -1;
	}

	if (EVP_DecryptUpdate(s->ctx, element->o_data, &len,
			      element->i_data, element->data_len) != 1) {
		ENGINE_ERR_print_errors();
		return -1;
	}

	return 0;
}

static int openssl_cipher_payload_finalise(struct crypto_visitor_ctx *ctx,
					   struct crypto_chain_elem *element)
{
	struct crypto_session *s = ctx_session(ctx);
	int len;

	if (EVP_CipherFinal_ex(s->ctx, element->o_data, &len) != 1) {
		ENGINE_ERR_print_errors();
		return -1;
	}

	return len;
}

static int openssl_hmac_update(struct crypto_visitor_ctx *ctx,
			       struct crypto_chain_elem *element)
{
	struct crypto_session *session = ctx_session(ctx);

	if (hmac_update(session, element->i_data, element->data_len) < 0) {
		ENGINE_PKT_ERR("Digest updated failed\n");
		return -1;
	}

	return 0;
}

static int openssl_hmac_finalise(struct crypto_visitor_ctx *ctx,
				 struct crypto_chain_elem *element)
{
	struct crypto_session *session = ctx_session(ctx);
	uint32_t md_len = 0;

	if (!HMAC_Final(session->hmac_ctx, element->o_data, &md_len)) {
		ENGINE_ERR("Digest finalise failed\n");
		return -1;
	}

	return 0;
}

static int null_hmac_update(struct crypto_visitor_ctx *ctx __rte_unused,
			    struct crypto_chain_elem *element __rte_unused)
{
	return 0;
}

static int null_hmac_set_icv(struct crypto_visitor_ctx *ctx __rte_unused,
			     unsigned int length __rte_unused,
			     unsigned char icv[] __rte_unused)
{
	return 0;
}

static int
openssl_null_hmac_set_auth_key(struct crypto_session *ctx __rte_unused)
{
	return 0;
}

const struct crypto_visitor_operations
default_decrypt_openssl_vops = {
	.set_iv = openssl_cipher_set_iv,
	.set_icv = openssl_hmac_set_icv,

	.payload_iv = openssl_hmac_update,
	.payload_block = openssl_hmac_decrypt_payload_block,
	.payload_finalise = openssl_cipher_payload_finalise,
	.header_block = openssl_hmac_update,
	.icv_finalise = openssl_hmac_finalise,
};

const struct crypto_visitor_operations
default_encrypt_openssl_vops = {
	.set_iv = openssl_cipher_set_iv,
	.set_icv = openssl_hmac_set_icv,

	.payload_iv = openssl_hmac_update,
	.payload_block = openssl_encrypt_hmac_payload_block,
	.payload_finalise = openssl_cipher_payload_finalise,
	.header_block = openssl_hmac_update,
	.icv_finalise = openssl_hmac_finalise,
};

const struct crypto_visitor_operations
null_hmac_decrypt_openssl_vops = {
	.set_iv = openssl_cipher_set_iv,
	.set_icv = null_hmac_set_icv,

	.payload_iv = null_hmac_update,
	.payload_block = openssl_hmac_decrypt_payload_block,
	.payload_finalise = openssl_cipher_payload_finalise,
	.header_block = null_hmac_update,
	.icv_finalise = null_hmac_update,
};

const struct crypto_visitor_operations
null_hmac_encrypt_openssl_vops = {
	.set_iv = openssl_cipher_set_iv,
	.set_icv = null_hmac_set_icv,

	.payload_iv = null_hmac_update,
	.payload_block = openssl_encrypt_hmac_payload_block,
	.payload_finalise = openssl_cipher_payload_finalise,
	.header_block = null_hmac_update,
	.icv_finalise = null_hmac_update,
};

/*
 * Based on RFC4303, Section 2, Table 1 + 2.
 */
static int crypto_chain_visit(const struct crypto_visitor_operations *v_ops,
			      struct crypto_visitor_ctx *ctx,
			      struct crypto_chain_elem *element)
{
	int ret = 0;

	/* ESP header */
	if (element->flags == ENG_DIGEST_BLOCK) {
		ret = v_ops->header_block(ctx, element);
		if (ret)
			goto out;
	}

	/* ESP payload: IV */
	if (element->flags == (ENG_CIPHER_INIT | ENG_DIGEST_BLOCK)) {
		ret = v_ops->payload_iv(ctx, element);
		if (ret)
			goto out;
	}

	/* ESP payload: data + padding + next hdr */
	if (element->flags & ENG_CIPHER_BLOCK) {
		ret = v_ops->payload_block(ctx, element);
		if (ret)
			goto out;
	}

	/* ESP payload: finalise */
	if (element->flags & ENG_CIPHER_FINALISE) {
		ret = v_ops->payload_finalise(ctx, element);
		if (ret)
			goto out;
	}

	/* ESP ICV callback */
	if (element->flags & ENG_DIGEST_FINALISE) {
		ret = v_ops->icv_finalise(ctx, element);
		if (ret)
			goto out;
	}

out:
	return ret;
}

static int crypto_chain_visitor_walk(
	const struct crypto_visitor_operations *v_ops,
	struct crypto_chain *chain)
{
	unsigned int i;

	if (unlikely(chain->index > MAX_CRYPTO_ENG_CMDS)) {
		ENGINE_PKT_ERR("Exceeded Max Chain Elements\n");
		return -1;
	}

	for (i = 0 ; i < chain->index ; ++i) {
		if (crypto_chain_visit(v_ops, chain->v_ctx, &chain->elem[i]))
			return -1;
	}

	chain->index = 0;
	return 0;
}

static void crypto_chain_set_element(struct crypto_chain_elem *element,
				     unsigned char *i_data,
				     unsigned char *o_data,
				     unsigned int data_len, uint32_t flags)
{
	element->i_data = i_data;
	element->o_data = o_data;
	element->data_len = data_len;
	element->flags = flags;
}

struct crypto_chain_elem *
crypto_chain_add_element(struct crypto_chain *chain,
			 unsigned char *i_data,
			 unsigned char *o_data,
			 unsigned int data_len,
			 uint32_t flags)
{
	struct crypto_chain_elem *element;

	if (chain->index >= MAX_CRYPTO_ENG_CMDS)
		return NULL;

	element = &chain->elem[chain->index++];
	crypto_chain_set_element(element, i_data, o_data, data_len, flags);
	return element;
}

int crypto_chain_walk(struct crypto_chain *chain)
{
	if (chain->v_ops)
		return crypto_chain_visitor_walk(chain->v_ops, chain);

	return -1;
}

static int openssl_session_cipher_init(struct crypto_session *s);

const struct crypto_visitor_operations *
crypto_session_get_vops(struct crypto_session *session)
{
	return session->direction == XFRM_POLICY_OUT ?
		session->s_ops->encrypt_vops :
		session->s_ops->decrypt_vops;
}

int crypto_chain_init(struct crypto_chain *chain,
		      struct crypto_session *session)
{
	/*
	 * FIXME: Once we have enough information about the policy direction
	 * when creating the crypto_session cipher_init() should only get
	 * called from set_enc_key().
	 */
	if (!session || openssl_session_cipher_init(session))
		return -1;

	chain->ctx = session;
	/* can't be -1 since openssl_session_cipher_init returned true */
	chain->encrypt = session->direction;
	/* initialize the crypto visitor */
	chain->v_ops = crypto_session_get_vops(session);
	chain->index = 0;
	return 0;
}

int crypto_session_set_enc_key(struct crypto_session *session)
{
	if (!session->s_ops->set_enc_key) {
		ENGINE_DEBUG("Function not supported: set_enc_key()\n");
		return -ENOTSUP;
	}

	return session->s_ops->set_enc_key(session);
}

int crypto_session_set_auth_key(struct crypto_session *session)
{
	if (!session->s_ops->set_auth_key) {
		ENGINE_DEBUG("Function not supported: set_auth_key()\n");
		return -ENOTSUP;
	}

	return session->s_ops->set_auth_key(session);
}

int crypto_session_generate_iv(struct crypto_session *session,
			       char iv[])
{
	if (!session->s_ops->generate_iv) {
		ENGINE_DEBUG("Function not supported: generate_iv()\n");
		return -ENOTSUP;
	}

	return session->s_ops->generate_iv(session, iv);
}

int crypto_session_set_iv(struct crypto_session *session, unsigned int length,
			  const char iv[])
{
	if (session->s_ops->set_iv)
		return session->s_ops->set_iv(session, length, iv);

	return 0;
}

static int setup_cipher_type(struct crypto_session *ctx,
			     const char *algo_name,
			     const uint32_t key_len)
{
	if (strcmp("cbc(aes)", algo_name) == 0) {
		switch (key_len) {
		case 128:
			ctx->cipher = EVP_aes_128_cbc();
			return 0;
		case 192:
			ctx->cipher = EVP_aes_192_cbc();
			return 0;
		case 256:
			ctx->cipher = EVP_aes_256_cbc();
			return 0;
		default:
			ENGINE_ERR("Unsupported cbc(aes) key size %d\n",
				   key_len);
			return -1;
		}
	}

	if (strcmp("cbc(des3_ede)", algo_name) == 0) {
		ctx->cipher = EVP_des_ede3_cbc();
		return 0;
	}

	if (strcmp("rfc4106(gcm(aes))", algo_name) == 0) {
		switch (key_len) {
		case 160:
			ctx->cipher = EVP_aes_128_gcm();
			return 0;
		case 288:
			ctx->cipher = EVP_aes_256_gcm();
			return 0;
		default:
			ENGINE_ERR("Unsupported gcm(aes) key size: %d\n",
				   key_len);
			return -1;
		}
	}

	if (strcmp("eNULL", algo_name) == 0 ||
	    strcmp("ecb(cipher_null)", algo_name) == 0) {
		ctx->cipher = EVP_enc_null();
		return 0;
	}
	ENGINE_ERR("Unsupported crypto algo %s\n", algo_name);
	return  -1;
}

static int setup_md_type(struct crypto_session *ctx,
			 const char *algo_name,
			 const uint32_t alg_trunc_len __unused)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(md_algorithms); i++)
		if (!strcmp(md_algorithms[i].name, algo_name)) {
			ctx->md = md_algorithms[i].fn();
			return 0;
		}

	ENGINE_ERR("Unsupported digest algo %s\n", algo_name);
	return -1;
}

int openssl_session_cipher_init(struct crypto_session *s)
{
	int encrypt = s->direction == XFRM_POLICY_OUT;

	if (likely(s->cipher_init || !s->block_size))
		return 0;

	s->ctx = EVP_CIPHER_CTX_new();
	if (!s->ctx) {
		ENGINE_ERR_print_errors();
		return -1;
	}

	if (EVP_CipherInit_ex(s->ctx, s->cipher, NULL,
			      s->key, NULL, encrypt) != 1) {
		ENGINE_ERR_print_errors();
		EVP_CIPHER_CTX_free(s->ctx);
		s->ctx = NULL;
		return -1;
	}
	if (EVP_CIPHER_mode(s->cipher) == EVP_CIPH_GCM_MODE) {
		if (!EVP_CIPHER_CTX_ctrl(s->ctx, EVP_CTRL_GCM_SET_IVLEN,
					 s->nonce_len + s->iv_len, NULL)) {
			EVP_CIPHER_CTX_free(s->ctx);
			s->ctx = NULL;
			ENGINE_ERR_print_errors();
			return -1;
		}
	}
	if (EVP_CIPHER_CTX_set_padding(s->ctx, 0) != 1) {
		EVP_CIPHER_CTX_free(s->ctx);
		s->ctx = NULL;
		ENGINE_ERR_print_errors();
		return -1;
	}

	s->cipher_init = 1;
	return 0;
}

static int openssl_session_set_enc_key(struct crypto_session *ctx)
{
	if ((ctx->direction != -1) &&
	    openssl_session_cipher_init(ctx))
		return -1;

	return 0;
}

static int openssl_session_set_auth_key(struct crypto_session *ctx)
{
	ctx->hmac_ctx = HMAC_CTX_new();
	if (!ctx->hmac_ctx) {
		ENGINE_ERR_print_errors();
		return -1;
	}

	if (!HMAC_Init_ex(ctx->hmac_ctx,
			  ctx->auth_alg_key,
			  ctx->auth_alg_key_len,
			  ctx->md, NULL)) {
		HMAC_CTX_free(ctx->hmac_ctx);
		ctx->hmac_ctx = NULL;
		ENGINE_ERR_print_errors();
		return -1;
	}

	return 0;
}

static int openssl_session_generate_iv(struct crypto_session *ctx, char iv[])
{
	memcpy(iv, &ctx->iv, crypto_session_iv_len(ctx));
	return 0;
}

static int openssl_session_set_iv(struct crypto_session *ctx,
				  unsigned int length,
				  const char iv[])
{
	if (length != crypto_session_iv_len(ctx)) {
		ENGINE_ERR("Unexpect IV length: %d\n", length);
		return -1;
	}

	/* Stash IV for next packet on SA. */
	memcpy(&ctx->iv, iv, length);
	return 0;
}

const struct crypto_session_operations default_openssl_sops = {
	.decrypt_vops = &default_decrypt_openssl_vops,
	.encrypt_vops = &default_encrypt_openssl_vops,
	.set_enc_key = openssl_session_set_enc_key,
	.set_auth_key = openssl_session_set_auth_key,
	.generate_iv = openssl_session_generate_iv,
	.set_iv = openssl_session_set_iv,
};

const struct crypto_session_operations null_hmac_openssl_sops = {
	.decrypt_vops = &null_hmac_decrypt_openssl_vops,
	.encrypt_vops = &null_hmac_encrypt_openssl_vops,
	.set_enc_key = openssl_session_set_enc_key,
	.set_auth_key = openssl_null_hmac_set_auth_key,
	.generate_iv = openssl_session_generate_iv,
	.set_iv = openssl_session_set_iv,
};

int crypto_openssl_session_setup(struct crypto_session *sess __unused)
{
	return 0;
}

void crypto_openssl_session_teardown(struct crypto_session *sess __unused)
{
}

struct crypto_session *
crypto_session_create(const struct xfrm_algo *algo_crypt,
		      const struct xfrm_algo_auth *algo_auth,
		      int direction)
{
	struct crypto_session *ctx;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	/* set up DPDK versions of data structures */
	if (crypto_rte_set_session_parameters(ctx, algo_crypt, algo_auth)) {
		RTE_LOG(ERR, DATAPLANE,
			"Failed to set session parameters for %s %s\n",
			algo_crypt->alg_name,
			algo_auth ? algo_auth->alg_name : "");
		goto err;
	}

	if (algo_auth)
		ctx->s_ops = &default_openssl_sops;
	else
		ctx->s_ops = &null_hmac_openssl_sops;

	ctx->direction = direction;

	if (algo_crypt) {
		ENGINE_DEBUG("Setup Cipher %s%d\n", algo_crypt->alg_name,
			     algo_crypt->alg_key_len);
		if (setup_cipher_type(ctx, algo_crypt->alg_name,
				      algo_crypt->alg_key_len) != 0)
			goto err;
		ctx->block_size = EVP_CIPHER_block_size(ctx->cipher);
		RAND_bytes((unsigned char *)ctx->iv, ctx->iv_len);
	}

	if  (algo_auth) {
		ENGINE_DEBUG("Setup Digest %s\n", algo_auth->alg_name);
		if (setup_md_type(ctx, algo_auth->alg_name,
				  algo_auth->alg_trunc_len) != 0)
			goto err;
	}

	return ctx;

err:
	free(ctx);
	return NULL;
}

void crypto_session_destroy(struct crypto_session *ctx)
{
	if (!ctx)
		return;

	crypto_openssl_session_teardown(ctx);

	if (ctx->hmac_ctx)
		HMAC_CTX_free(ctx->hmac_ctx);
	if (ctx->ctx)
		EVP_CIPHER_CTX_free(ctx->ctx);

	free(ctx);
}

static int check_algorithmic_requirements(const struct xfrm_algo *crypt,
					  const struct xfrm_algo_auth *auth)
{
	/* check RFC4301 */
	if (!crypt && !auth) {
		ENGINE_ERR("Invalid algorithmic combination: both NULL\n");
		return -1;
	}

	if (!crypt)	/* only has authentication */
		return 0;

	/* check RFC4835 */
	if (strcmp("cbc(des)", crypt->alg_name) == 0) {
		ENGINE_ERR("Invalid encryption algorithmic: DES-CBC\n");
		return -1;
	}

	/* check RFC3686 */
	if ((strcmp("ctr(aes)", crypt->alg_name) == 0) && !auth) {
		ENGINE_ERR("Invalid AES-CTR authentication method: NULL\n");
		return -1;
	}

	return 0;
}

int cipher_setup_ctx(const struct xfrm_algo *algo_crypt,
		     const struct xfrm_algo_auth *algo_auth,
		     const struct xfrm_usersa_info *sa_info,
		     const struct xfrm_encap_tmpl *tmpl,
		     struct sadb_sa *sa, uint32_t extra_flags)
{
	int ret;

	if (check_algorithmic_requirements(algo_crypt, algo_auth))
		return -1;

	sa->session = crypto_session_create(algo_crypt, algo_auth, -1);
	if (!sa->session)
		return -1;

	if (algo_crypt) {
		ret = crypto_session_set_enc_key(sa->session);
		if (ret) {
			ENGINE_ERR("Failed to set session encryption key\n");
			return ret;
		}
	}
	if (algo_auth) {
		ret = crypto_session_set_auth_key(sa->session);
		if (ret) {
			ENGINE_ERR("Failed to set session integrity key\n");
			return ret;
		}
	}

	sa->udp_encap = 0;
	if (tmpl) {
		if (tmpl->encap_type == UDP_ENCAP_ESPINUDP) {
			sa->udp_encap = 1;
			sa->udp_sport = tmpl->encap_sport;
			sa->udp_dport = tmpl->encap_dport;
		} else {
			ENGINE_ERR("Unknown Encap\n");
			return -1;
		}
	}

	sa->mode = sa_info->mode;
	sa->spi = sa_info->id.spi;

	if ((sa->mode != XFRM_MODE_TRANSPORT) &&
	    (sa->mode != XFRM_MODE_TUNNEL)) {
		ENGINE_ERR("XFRM: unsupported mode %#x\n", sa->mode);
		return -1;
	}

	sa->seq = 0;
	sa->replay_bitmap = 0;
	sa->replay_window = sa_info->replay_window;

	sa->flags = sa_info->flags;
	sa->extra_flags = extra_flags;

	if (sa_info->family == AF_INET) {
		sa->iphdr = (struct iphdr){
			.saddr = sa_info->saddr.a4,
			.daddr = sa_info->id.daddr.a4,
			.ttl = 255,
			.ihl = 5,
			.version = IPVERSION,
			.protocol = sa->udp_encap ? IPPROTO_UDP : IPPROTO_ESP,
		};
		sa->iphdr.check = dp_in_cksum_hdr(&sa->iphdr);
	} else {
		struct ip6_hdr *ip6_hdr =  &sa->ip6_hdr;

		ip6_hdr->ip6_vfc = IPV6_VERSION;
		memcpy(&ip6_hdr->ip6_src, sa_info->saddr.a6,
		       sizeof(struct in6_addr));
		memcpy(&ip6_hdr->ip6_dst, sa_info->id.daddr.a6,
		       sizeof(struct in6_addr));
		ip6_hdr->ip6_hlim = 64;
		ip6_hdr->ip6_nxt = sa->udp_encap ? IPPROTO_UDP : IPPROTO_ESP;
	}
	return 0;
}

void cipher_teardown_ctx(struct sadb_sa *sa)
{
	crypto_session_destroy(sa->session);
	sa->session = NULL;
}

uint32_t cipher_get_encryption_overhead(struct sadb_sa *sa,
					uint16_t family)
{
	uint32_t overhead;

	/*
	 * The fixed parts of the overhead are 8 bytes for the ESP header
	 * plus 2 bytes for the ESP trailer (pad length + next header).
	 */
	overhead = 8 + 2;

	/*
	 * Since the padding of the ESP payload depends on the payload data
	 * length it needs to get accounted for separately.
	 *
	 * Also see: crypto_policy_handle_packet_outbound()
	 */

	if (sa->session)
		overhead += crypto_session_iv_len(sa->session);

	/*
	 * For tunnel mode, add space for the outer IP header.
	 */
	if (sa->mode == XFRM_MODE_TUNNEL)
		overhead += (family == AF_INET) ?
			sizeof(struct iphdr) :
			sizeof(struct ip6_hdr);
	/*
	 * And another 8 bytes for the UDP header if required
	 */
	if (sa->udp_encap)
		overhead += 8;
	/*
	 * If there is an ICV add its length
	 */
	if (sa->session)
		overhead += crypto_session_digest_len(sa->session);

	return overhead;
}

void crypto_engine_load(void)
{
	ENGINE_DEBUG("Cryptolib init\n");
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG |
			    OPENSSL_INIT_ENGINE_ALL_BUILTIN, NULL);
	OpenSSL_add_all_digests();
}

void crypto_engine_summary(json_writer_t *wr, const struct sadb_sa *sa)
{
	struct crypto_session *sess;

	if (!sa->session)
		return;

	sess = sa->session;

	if (sess->aead_algo != RTE_CRYPTO_AEAD_LIST_END) {
		jsonw_string_field(
			wr, "cipher",
			rte_crypto_aead_algorithm_strings[sess->aead_algo]);
		jsonw_uint_field(
			wr, "cipher_key_len",
			(sess->key_len - sess->nonce_len) * BITS_PER_BYTE);
	} else if (sess->cipher_algo != RTE_CRYPTO_CIPHER_LIST_END) {
		jsonw_string_field(
			wr, "cipher",
			rte_crypto_cipher_algorithm_strings[
				sess->cipher_algo]);
		jsonw_uint_field(wr, "cipher_key_len",
				 sess->key_len * BITS_PER_BYTE);
	} else
		jsonw_string_field(wr, "cipher", "Unknown");

	jsonw_string_field(wr, "digest",
			   rte_crypto_auth_algorithm_strings[sess->auth_algo]);
}

static int crypto_chain_dump_set_iv(struct crypto_visitor_ctx *ctx,
				    unsigned int memsize,
				    const unsigned char memory[])
{
	const struct crypto_visitor_operations *vops =
		crypto_session_get_vops(ctx->session);

	ENGINE_DEBUG("set_iv => %d bytes @ %p\n", memsize, memory);
	dump_data(memory, memsize);
	return vops->set_iv(ctx, memsize, memory);
}

static int crypto_chain_dump_set_icv(struct crypto_visitor_ctx *ctx,
				     unsigned int memsize,
				     unsigned char memory[])
{
	const struct crypto_visitor_operations *vops =
		crypto_session_get_vops(ctx->session);

	ENGINE_DEBUG("set_icv => %d bytes @ %p\n", memsize, memory);
	dump_data(memory, memsize);
	return vops->set_icv(ctx, memsize, memory);
}

static int crypto_chain_dump_elem(struct crypto_visitor_ctx *ctx,
				  struct crypto_chain_elem *data)
{
	const struct crypto_visitor_operations *vops =
		crypto_session_get_vops(ctx->session);
	char buffer[ENG_CMD_STR_BUF_SIZE];
	int ret;

	if (data->i_data) {
		ENGINE_DEBUG("i_data type %s => %u bytes @ %p\n",
			     crypto_engine_cmd2str(data->flags, buffer,
						   ENG_CMD_STR_BUF_SIZE) ?
			     buffer : "none", data->data_len, data->i_data);
		dump_data(data->i_data, data->data_len);
	}

	ret = crypto_chain_visit(vops, ctx, data);

	if (data->o_data) {
		ENGINE_DEBUG("o_data type %s => %u bytes @ %p\n",
			     crypto_engine_cmd2str(data->flags, buffer,
						   ENG_CMD_STR_BUF_SIZE) ?
			     buffer : "none", data->data_len, data->o_data);
		dump_data(data->o_data, data->data_len);
	}

	return ret;
}

/*
 * A crypto chain visitor that outputs the data to ENGINE_DEBUG() and forwards
 * to the session visitor.
 */
const struct crypto_visitor_operations crypto_chain_dump_vops = {
	.set_iv = crypto_chain_dump_set_iv,
	.set_icv = crypto_chain_dump_set_icv,

	.payload_iv = crypto_chain_dump_elem,
	.payload_block = crypto_chain_dump_elem,
	.payload_finalise = crypto_chain_dump_elem,
	.header_block = crypto_chain_dump_elem,
	.icv_finalise = crypto_chain_dump_elem,
};

const struct crypto_visitor_operations *
crypto_chain_dump_get_vops(void)
{
	return &crypto_chain_dump_vops;
}

/*
 * libcrypto locking mechanism callbacks for multi threading
 */
static pthread_mutex_t *lockarray;

/*
 * Declare
 *
 *  lock_callback
 *  my_thread_id
 *
 * as non static as a temporary fix to deb9 build issue
 * which uses a new version of libcrpyto, whilst we understand the locking
 * changes in the new lib.
 */
void lock_callback(int mode, int type, __unused const char *file,
		   __unused int line)
{
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(&(lockarray[type]));
	else
		pthread_mutex_unlock(&(lockarray[type]));
}

unsigned long my_thread_id(void)
{
	unsigned long ret;

	ret = (unsigned long)pthread_self();
	return ret;
}

void crypto_engine_init(void)
{
	int i;

	lockarray = OPENSSL_malloc(CRYPTO_num_locks() *
				   sizeof(*lockarray));
	for (i = 0; i < CRYPTO_num_locks(); i++)
		(void)pthread_mutex_init(&(lockarray[i]), NULL);

	CRYPTO_set_id_callback(my_thread_id);
	CRYPTO_set_locking_callback(lock_callback);
}

void crypto_engine_shutdown(void)
{
	int i;

	CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++)
		(void)pthread_mutex_destroy(&(lockarray[i]));

	OPENSSL_free(lockarray);
}
