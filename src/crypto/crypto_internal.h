/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef CRYPTO_INTERNAL_H
#define CRYPTO_INTERNAL_H

#include <stdint.h>
#include <linux/xfrm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <rte_log.h>
#include <rte_memcpy.h>
#include <rte_mbuf.h>
#include <sys/queue.h>

#include "crypto_main.h"
#include "json_writer.h"
#include "vplane_log.h"
#include "vrf.h"

#define CRYPTO_DATA_ERR(args...)			\
	DP_DEBUG(CRYPTO_DATA, ERR, CRYPTO, args)

#define CRYPTO_ERR(args...)			\
	DP_DEBUG(CRYPTO, ERR, CRYPTO, args)

#define CRYPTO_INFO(args...)			\
	DP_DEBUG(CRYPTO, ERR, CRYPTO, args)

#define PMD_RING_SIZE  4096

#define SPI_LEN_IN_HEXCHARS (8+1) /* 32 bit SPI */

static inline void spi_to_hexstr(char *buf, uint32_t spi)
{
	snprintf(buf, SPI_LEN_IN_HEXCHARS, "%.8x", spi);
}
/****************************************************
 * Change this to a #define to enable the DEBUG flag
 *
 * DO NOT COMMIT A CHANGE TO THIS FLAG
 ****************************************************/
#undef CRYPTO_LOG_NOTICE_FOR_DEBUG
/****************************************************/

struct crypto_dp {
	struct rte_mempool *pool;
	struct rte_ring *crypto_q[MAX_CRYPTO_XFRM];
};

#if !HAVE_DECL_HMAC_CTX_NEW
static inline HMAC_CTX *HMAC_CTX_new(void)
{
	return (HMAC_CTX *)calloc(1, sizeof(HMAC_CTX));
}

static inline void HMAC_CTX_free(HMAC_CTX *ctx)
{
	HMAC_CTX_cleanup(ctx);
	free(ctx);
}

struct ossl_init_settings_st {
	char *appname;
};

# define OPENSSL_INIT_LOAD_CRYPTO_STRINGS    0x00000002L
# define OPENSSL_INIT_NO_ADD_ALL_DIGESTS     0x00000020L
# define OPENSSL_INIT_LOAD_CONFIG            0x00000040L
# define OPENSSL_INIT_NO_LOAD_CONFIG         0x00000080L
# define OPENSSL_INIT_ASYNC                  0x00000100L
# define OPENSSL_INIT_ENGINE_RDRAND          0x00000200L
# define OPENSSL_INIT_ENGINE_DYNAMIC         0x00000400L
# define OPENSSL_INIT_ENGINE_OPENSSL         0x00000800L
# define OPENSSL_INIT_ENGINE_CRYPTODEV       0x00001000L
# define OPENSSL_INIT_ENGINE_CAPI            0x00002000L
# define OPENSSL_INIT_ENGINE_PADLOCK         0x00004000L
# define OPENSSL_INIT_ENGINE_AFALG           0x00008000L

# define OPENSSL_INIT_ENGINE_ALL_BUILTIN \
	(OPENSSL_INIT_ENGINE_RDRAND | OPENSSL_INIT_ENGINE_DYNAMIC	\
	 | OPENSSL_INIT_ENGINE_CRYPTODEV | OPENSSL_INIT_ENGINE_CAPI |	\
	 OPENSSL_INIT_ENGINE_PADLOCK)

static inline void
OPENSSL_init_crypto(uint32_t opts __attribute__ ((__unused__)),
		    const struct ossl_init_settings_st *settings
		    __attribute__ ((__unused__)))
{
	OPENSSL_config(NULL);
}
#endif

#define CRYPTO_PMD_INVALID_ID -1

struct crypto_session_operations;
struct crypto_visitor_operations;

enum crypto_dir {
	CRYPTO_DIR_IN = 0,
	CRYPTO_DIR_OUT
};

struct crypto_session {
	/* All perpacket in first cacheline */
	const struct crypto_session_operations *s_ops;
	int8_t direction;	/* -1 | XFRM_POLICY_IN | _OUT*/
	uint8_t cipher_init;
	uint16_t digest_len;	/* in bytes */
	uint16_t block_size;    /* in bytes */
	uint16_t iv_len;        /* in bytes */
	EVP_CIPHER_CTX *ctx;
	HMAC_CTX *hmac_ctx;
	uint16_t nonce_len;     /* in bytes */
	char iv[EVP_MAX_IV_LENGTH];
	/*
	 * Max nonce slips into 2rd cacheline, however normal use case
	 * aes128g/256gcm is 4 bytes and so it is within first cache
	 * line
	 */
	unsigned char nonce[EVP_MAX_IV_LENGTH];
	/* Cacheline1 */
	uint16_t key_len;	/* in bytes */
	uint16_t auth_alg_key_len; /* in bytes */
	uint8_t key[EVP_MAX_KEY_LENGTH];
	char auth_alg_name[64];
	char auth_alg_key[EVP_MAX_KEY_LENGTH];

	const EVP_CIPHER *cipher;
	const EVP_MD *md;
	const char *md_name;
	const char *cipher_name;
};

/*
 * struct sadb_sa
 *
 * This struct contains the information associated with
 * a security association with an IPsec peer. The crypto
 * context is populated and maintained (i.e. possibly
 * written to) by the crypto engine. All other fields are
 * populated at the time the SA is created in the main
 * thread and are considered read only in all threads
 * thereafter.
 */
struct sadb_sa {
	struct cds_lfht_node spi_ht_node;
	uint32_t spi; /* Network byte order */
	uint32_t mark_val;
	bool blocked;
	char SPARE1;
	uint16_t family;
	enum crypto_dir dir;
	struct iphdr iphdr;
	uint8_t mode;
	/* Following three fields are for use with
	 * NAT'ed paths
	 */
	uint8_t udp_encap;
	uint16_t id;
	struct crypto_session *session;
	/* Cacheline 1 boundary */
	uint16_t udp_sport;
	uint16_t udp_dport;
	uint32_t seq;
	uint32_t flags;
	uint32_t extra_flags;
	uint64_t packet_count;
	uint64_t packet_limit;
	uint64_t byte_count;
	uint64_t byte_limit;
	/* Cacheline 2 boundary */
	xfrm_address_t dst;
	struct cds_list_head peer_links;
	uint32_t reqid;
	int pmd_dev_id;
	struct rcu_head sa_rcu;
	xfrm_address_t src;
	uint32_t seq_drop;
	int del_pmd_dev_id;
	/* Cacheline 3 boundary */
	uint8_t replay_window;
	uint8_t pending_del;
	uint64_t replay_bitmap;
	struct ip6_hdr ip6_hdr;
	struct ifnet *feat_attach_ifp;
	vrfid_t overlay_vrf_id;
};

struct crypto_chain_elem;

struct crypto_session_operations {
	const struct crypto_visitor_operations *decrypt_vops;
	const struct crypto_visitor_operations *encrypt_vops;
	int (*set_enc_key)(struct crypto_session *session,
			   unsigned int length, const char key[]);
	int (*set_auth_key)(struct crypto_session *session,
			    unsigned int length, const char key[]);
	int (*generate_iv)(struct crypto_session *session, char iv[]);
	int (*set_iv)(struct crypto_session *session,
		      unsigned int length, const char iv[]);

	int (*decrypt_walk)(struct crypto_session *sa,
			    struct crypto_chain_elem *data,
			    unsigned int length);
	int (*encrypt_walk)(struct crypto_session *sa,
			    struct crypto_chain_elem *data,
			    unsigned int length);

};

/*
 * This type is a helper for type-safe passing of the visitor specific
 * contexts. A visitor implementation might embed it and use container_of()
 * to access its type specific struct.
 */
struct crypto_visitor_ctx {
	struct crypto_session *session;
};

struct crypto_visitor_operations {
	int (*set_iv)(struct crypto_visitor_ctx *ctx,
		      unsigned int length, const unsigned char iv[]);
	int (*set_icv)(struct crypto_visitor_ctx *ctx,
		       unsigned int length, unsigned char icv[]);

	int (*header_block)(struct crypto_visitor_ctx *ctx,
			    struct crypto_chain_elem *element);
	int (*payload_iv)(struct crypto_visitor_ctx *ctx,
			  struct crypto_chain_elem *element);
	int (*payload_block)(struct crypto_visitor_ctx *ctx,
			     struct crypto_chain_elem *element);
	int (*payload_finalise)(struct crypto_visitor_ctx *ctx,
				struct crypto_chain_elem *element);
	int (*icv_finalise)(struct crypto_visitor_ctx *ctx,
			    struct crypto_chain_elem *element);
};

const struct crypto_visitor_operations *
crypto_session_get_vops(struct crypto_session *session);

const struct crypto_visitor_operations *
crypto_chain_dump_get_vops(void);

static inline uint32_t
crypto_session_block_size(const struct crypto_session *ctx)
{
	return ctx->block_size;
}

static inline uint32_t
crypto_session_iv_len(const struct crypto_session *ctx)
{
	return ctx->iv_len;
}

static inline uint32_t
crypto_session_digest_len(const struct crypto_session *ctx)
{
	return ctx->digest_len;
}

int crypto_session_set_enc_key(struct crypto_session *session,
			       unsigned int length, const char key[]);
int crypto_session_set_auth_key(struct crypto_session *session,
				unsigned int length,
				const char key[]);
int crypto_session_generate_iv(struct crypto_session *session,
			       char iv[]);
int crypto_session_set_iv(struct crypto_session *session, unsigned int length,
			  const char iv[]);

struct crypto_session *
crypto_session_create(const struct xfrm_algo *algo_crypt,
		      const struct xfrm_algo_auth *algo_auth,
		      int direction);

void crypto_session_destroy(struct crypto_session *ctx);

/*
 * DEPRECATED: This function is a temporary helper to set the crypto_session
 * direction. It will be removed as soon as the policy direction is can get
 * resolved on crypto_session creation.
 */
static inline void
crypto_session_set_direction(struct crypto_session *ctx, int direction)
{
	if (unlikely(ctx->direction == -1))
		ctx->direction = direction;
}

/*
 * Returns TRUE if two IPv4 (or IPv6) addresses are equal.
 */
static inline int xfrm_addr_eq(const xfrm_address_t *addr_1,
			       const xfrm_address_t *addr_2,
			       unsigned int family)
{
	switch (family) {
	case AF_INET:
		return addr_1->a4 == addr_2->a4;
	case AF_INET6:
		return ((addr_1->a6[0] == addr_2->a6[0]) &&
			(addr_1->a6[1] == addr_2->a6[1]) &&
			(addr_1->a6[2] == addr_2->a6[2]) &&
			(addr_1->a6[3] == addr_2->a6[3]));
	default:
		break;
	}

	return 0;
}

/*
 * The crypto engine's crypto_chain_elem structure describe a memory region
 * to be processed by the crypto and message digest engine.
 */
struct crypto_chain_elem {
	unsigned char *i_data;
	unsigned char *o_data;
	unsigned int data_len;
	uint32_t flags;
};

#define MAX_CRYPTO_ENG_CMDS 8

/*
 * The crypto engine's crypto_chain is an abstraction layer between the ESP
 * and the actual implementation of the cryptographic operations. That way the
 * ESP layer doesn't need to know about details of the algorithms, e.g. if the
 * algorithm is able to handle encryption and hashing in one pass. Crypto and
 * message digest processing can operate in parallel on the same block of
 * memory, or individually.
 */
struct crypto_chain {
	struct crypto_session *ctx;
	/* the crypto visitor for this chain */
	const struct crypto_visitor_operations *v_ops;
	struct crypto_visitor_ctx *v_ctx;
	int (*icv_callback)(struct crypto_chain *, struct rte_mbuf *);
	unsigned int index;
	uint16_t icv_offset;
	int8_t encrypt;
	char SPARE[25];
	struct crypto_chain_elem elem[MAX_CRYPTO_ENG_CMDS];
	/* private */
	unsigned char slop_buffer[EVP_MAX_MD_SIZE]; /* > EVP_MAX_BLOCK_LENGTH */
};

/*
 * Crypto Engine commands
 */
enum {
	ENG_CIPHER_INIT = 1,
	ENG_DIGEST_INIT = 2,
	ENG_CIPHER_BLOCK = 4,
	ENG_DIGEST_BLOCK = 8,
	ENG_CIPHER_FINALISE = 16,
	ENG_DIGEST_FINALISE = 32,
	ENG_DIGEST_VERIFY = 64,
	ENG_CMD_MAX = 128
};

struct crypto_chain_elem *
crypto_chain_add_element(struct crypto_chain *chain,
			 unsigned char *i_data,
			 unsigned char *o_data,
			 unsigned int data_len,
			 uint32_t flags);

int crypto_chain_walk(struct crypto_chain *chain);

int crypto_chain_init(struct crypto_chain *chain,
		      struct crypto_session *session);

void crypto_engine_load(void);

int cipher_setup_ctx(const struct xfrm_algo *,
		     const struct xfrm_algo_auth *,
		     const struct xfrm_usersa_info *,
		     const struct xfrm_encap_tmpl *t,
		     struct sadb_sa *,
		     uint32_t extra_flags);
void cipher_teardown_ctx(struct sadb_sa *sa);

void crypto_engine_summary(json_writer_t *wr, const struct sadb_sa *sa);

#define IF_INCR_Mx(_ifp, _m, _x)		\
do {						\
	if (_ifp)				\
		if_incr ## _x(_ifp, _m);	\
} while (0)

#define IF_INCR_x(_ifp, _x)			\
do {						\
	if (_ifp)				\
		if_incr ## _x(_ifp);		\
} while (0)

#define IF_INCR_OERROR(_ifp)  IF_INCR_x(_ifp, _oerror)
#define IF_INCR_ERROR(_ifp)   IF_INCR_x(_ifp, _error)
#define IF_INCR_IN(_ifp, _m)  IF_INCR_Mx(_ifp, _m, _in)
#define IF_INCR_OUT(_ifp, _m) IF_INCR_Mx(_ifp, _m, _out)

extern uint32_t crypto_rekey_requests;

/*
 * Crypto overhead observer list and structure.
 *
 * These are used to by the policy database and VTI
 * interface code to subscribe to encryption overhead
 * information from the SADB
 */

TAILQ_HEAD(crypto_overhead_list, crypto_overhead);

struct crypto_overhead {
	TAILQ_ENTRY(crypto_overhead) links;
	uint32_t bytes;
	uint32_t reqid;
	int pmd_dev_id;
	uint spi;
	uint8_t block_size;
};

enum ipsec_cnt_types {
	ENQUEUED_INPUT_IPV4,
	ENQUEUED_INPUT_IPV6,
	ENQUEUED_OUTPUT_IPV4,
	ENQUEUED_OUTPUT_IPV6,
	DROPPED,
	DROPPED_NO_MBUF,
	DROPPED_IPV6_UNSUPPORTED,
	DROPPED_UNSUPPORTED_PROTOCOL,
	DROPPED_ESP_OUTPUT_FAIL,
	DROPPED_ESP_INPUT_FAIL,
	DROPPED_BAD_DIRECTION,
	DROPPED_NO_POLICY_RULE,
	DROPPED_POLICY_BLOCK,
	DROPPED_NO_NEXT_HOP,
	DROPPED_BLACKHOLE_OR_BROADCAST,
	DROPPED_FILTER_REJECT,
	DROPPED_OVERHEAD_TOO_BIG,
	DROPPED_DF,
	DROPPED_NO_CTX,
	DROPPED_INVALID_REQID,
	DROPPED_INVALID_VERSION,
	FAILED_TO_BURST,
	BURST_RING_FULL,
	FAILED_TO_ALLOCATE_CTX,
	NO_DST_SUPPLIED,
	CTX_ALLOCATED,
	CTX_FREED,
	FAILED_TO_RETURN,
	RETURNED,
	NO_IN_SA,
	NO_OUT_SA,
	NO_VTI,
	OUTSIDE_SEQ_WINDOW,
	DROPPED_NO_IFP,
	DROPPED_INVALID_PMD_DEV_ID,
	DROPPED_NO_SPI_TO_SA,
	PR_CACHE_ADD,
	PR_CACHE_ADD_FAIL,
	PR_CACHE_HIT,
	PR_CACHE_MISS,
	DROPPED_NO_BIND,
	DROPPED_ON_FP_NO_PR,
	IPSEC_CNT_MAX /* this must be last */
};

/*
 * per-VRF context block
 */
struct crypto_vrf_ctx {
	struct cds_lfht *input_policy_rule_sel_ht;
	struct cds_lfht *output_policy_rule_sel_ht;
	struct cds_lfht *spi_out_hash_table;
	struct cds_lfht *sadb_hash_table;
	struct cds_lfht *s2s_bind_hash_table;
	vrfid_t vrfid;
	uint32_t crypto_live_ipv6_policies;
	uint32_t crypto_live_ipv4_policies;
	unsigned int count_of_sas;
	unsigned int s2s_bindings;
	uint32_t count_of_peers;
	struct rcu_head vrf_ctx_rcu;
};

/*
 * tmp export to enable ring patching on pmd create
 */
extern struct crypto_dp *crypto_dp_sp;

extern unsigned long
ipsec_counters[RTE_MAX_LCORE][IPSEC_CNT_MAX] __rte_cache_aligned;

#define IPSEC_CNT_INC(_type) (ipsec_counters[dp_lcore_id()][_type]++)
#define IPSEC_CNT_INC_BY(_type, _cnt) \
	(ipsec_counters[dp_lcore_id()][_type] += _cnt)

uint32_t cipher_get_encryption_overhead(struct sadb_sa *sa,
					uint16_t family);

void crypto_sadb_peer_overhead_subscribe(const xfrm_address_t *peer_address,
					 uint16_t family, uint32_t reqid,
					 struct crypto_overhead *overhead,
					 vrfid_t vrfid);

void crypto_sadb_peer_overhead_unsubscribe(const xfrm_address_t *peer_address,
					   uint16_t family,
					   struct crypto_overhead *overhead,
					   vrfid_t vrfid);

int crypto_sadb_peer_overhead_change_reqid(const xfrm_address_t *peer_address,
					   uint16_t family, uint32_t reqid,
					   struct crypto_overhead *overhead,
					   vrfid_t vrfid);

int crypto_policy_get_vti_reqid(vrfid_t vrfid,
				const xfrm_address_t *peer, uint8_t family,
				uint32_t mark, uint32_t *reqid);

void vti_reqid_set(const xfrm_address_t *dst, uint8_t family,
		   uint32_t mark, uint32_t reqid);

void vti_reqid_clear(const xfrm_address_t *dst, uint8_t family, uint32_t mark);

void crypto_expire_request(uint32_t spi, uint32_t reqid,
			   uint8_t proto, uint8_t hard);
void crypto_engine_init(void);
void crypto_engine_shutdown(void);

void lock_callback(int mode, int type, const char *file, int line);
unsigned long my_thread_id(void);

struct rte_ring *crypto_create_ring(const char *name,
				    unsigned int count,
				    int socket_id,
				    unsigned int lcore_id,
				    unsigned int flags);
const char *crypto_xfrm_name(enum crypto_xfrm xfrm);
void crypto_purge_queue(struct rte_ring *pmd_queue);
void crypto_delete_queue(struct rte_ring *pmd_queue);
/*
 * Prototypes for crypto_pmd.c
 */
void crypto_remove_sa_from_pmd(int crypto_dev_id, enum crypto_xfrm xfrm,
			       bool pending);
int crypto_allocate_pmd(enum crypto_xfrm xfrm);
struct rte_ring *crypto_pmd_get_q(int dev_id, enum crypto_xfrm xfrm);
typedef bool (*crypto_pmd_walker_cb)(int pmd_dev_id, enum crypto_xfrm,
				     struct rte_ring *,
				     uint64_t *bytes,
				     uint32_t *packets);
unsigned int crypto_pmd_walk_per_xfrm(struct cds_list_head *pmd_head,
					      crypto_pmd_walker_cb cb);
void crypto_pmd_inc_pending_del(int pmd_dev_id, enum crypto_xfrm xfrm);
void crypto_pmd_dec_pending_del(int pmd_dev_id, enum crypto_xfrm xfrm);
struct crypto_vrf_ctx *crypto_vrf_find(vrfid_t vrfid);
struct crypto_vrf_ctx *crypto_vrf_find_external(vrfid_t vrfid);
struct crypto_vrf_ctx *crypto_vrf_get(vrfid_t vrfid);
void crypto_vrf_check_remove(struct crypto_vrf_ctx *vrf_ctx);
struct ifnet *crypto_policy_feat_attach_by_reqid(uint32_t reqid);
#endif /* CRYPTO_INTERNAL_H */
