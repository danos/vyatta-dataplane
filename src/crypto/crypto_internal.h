/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
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
#include <rte_cryptodev.h>
#include <rte_log.h>
#include <rte_memcpy.h>
#include <rte_mbuf.h>
#include <sys/queue.h>

#include "crypto_defs.h"
#include "crypto_main.h"
#include "json_writer.h"
#include "vplane_log.h"
#include "vrf_internal.h"
#include "crypto_rte_pmd.h"

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

#define CRYPTO_PMD_INVALID_ID -1

struct crypto_session_operations;
struct crypto_visitor_operations;

enum crypto_dir {
	CRYPTO_DIR_IN = 0,
	CRYPTO_DIR_OUT
};

struct crypto_openssl_info {
	const struct crypto_session_operations *s_ops;
	EVP_CIPHER_CTX     *ctx;
	HMAC_CTX           *hmac_ctx;
	const EVP_CIPHER   *cipher;
	const EVP_MD       *md;
};

struct crypto_session {
	/* All perpacket in first cacheline */

	struct rte_cryptodev_sym_session *rte_session;
	int8_t direction;	/* -1 | XFRM_POLICY_IN | _OUT*/
	uint8_t cipher_init;
	uint8_t digest_len;           /* in bytes */
	uint8_t block_size;           /* in bytes */
	uint8_t iv_len;               /* in bytes */
	uint8_t nonce_len;            /* in bytes */
	uint8_t key_len;	      /* in bytes */
	uint8_t auth_alg_key_len;     /* in bytes */
	char iv[CRYPTO_MAX_IV_LENGTH];
	unsigned char nonce[CRYPTO_MAX_IV_LENGTH];
	uint8_t key[CRYPTO_MAX_CIPHER_KEY_LENGTH];

	/* --- cacheline 1 boundary (64 bytes) was 16 bytes ago --- */

	/*
	 * For AES-128-GCM, all the data required should be within the
	 * first cacheline. For all other ciphers, it will take 2 cachelines
	 * to load all the required data
	 */
	char auth_alg_key[CRYPTO_MAX_AUTH_KEY_LENGTH];

	struct crypto_openssl_info *o_info;

	enum rte_crypto_aead_algorithm   aead_algo;
	enum rte_crypto_cipher_algorithm cipher_algo;

	/* --- cacheline 2 boundary (128 bytes) --- */

	enum rte_crypto_auth_algorithm   auth_algo;
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
	uint8_t rte_cdev_id;
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
	/* --- cacheline 1 boundary (64 bytes) --- */
	uint16_t udp_sport;
	uint16_t udp_dport;
	uint32_t seq;
	uint32_t flags;
	uint32_t extra_flags;
	uint64_t packet_count;
	uint64_t packet_limit;
	uint64_t byte_count;
	uint64_t byte_limit;
	xfrm_address_t dst;
	/* --- cacheline 2 boundary (128 bytes) --- */
	struct cds_list_head peer_links;
	uint32_t reqid;
	int pmd_dev_id;
	struct rcu_head sa_rcu;
	xfrm_address_t src;
	uint32_t seq_drop;
	int del_pmd_dev_id;
	/* --- cacheline 3 boundary (192 bytes) --- */
	uint8_t replay_window;
	uint8_t pending_del;
	uint64_t replay_bitmap;
	struct ip6_hdr ip6_hdr;
	struct ifnet *feat_attach_ifp;
	vrfid_t overlay_vrf_id;
	uint64_t epoch;
};

static_assert(offsetof(struct sadb_sa, udp_sport) == 64,
	      "first cache line exceeded");
static_assert(offsetof(struct sadb_sa, peer_links) == 128,
	      "second cache line exceeded");
static_assert(offsetof(struct sadb_sa, replay_window) == 192,
	      "third cache line exceeded");

struct crypto_chain_elem;

struct crypto_session_operations {
	const struct crypto_visitor_operations *decrypt_vops;
	const struct crypto_visitor_operations *encrypt_vops;
	int (*set_enc_key)(struct crypto_session *session);
	int (*set_auth_key)(struct crypto_session *session);
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

int crypto_session_set_enc_key(struct crypto_session *session);
int crypto_session_set_auth_key(struct crypto_session *session);

struct crypto_session *
crypto_session_create(const struct xfrm_algo *algo_crypt,
		      const struct xfrm_algo_auth *algo_auth,
		      int direction);

void crypto_session_destroy(struct crypto_session *ctx);

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

int crypto_engine_load(void);

int cipher_setup_ctx(const struct xfrm_algo *,
		     const struct xfrm_algo_auth *,
		     const struct xfrm_usersa_info *,
		     const struct xfrm_encap_tmpl *t,
		     struct sadb_sa *,
		     uint32_t extra_flags);
void cipher_teardown_ctx(struct sadb_sa *sa);

int crypto_openssl_session_setup(struct crypto_session *ctx);

void crypto_openssl_session_teardown(struct crypto_session *ctx);

void crypto_engine_summary(json_writer_t *wr, const struct sadb_sa *sa);

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
	FLOW_CACHE_ADD,
	FLOW_CACHE_ADD_FAIL,
	FLOW_CACHE_HIT,
	FLOW_CACHE_MISS,
	DROPPED_NO_BIND,
	DROPPED_ON_FP_NO_PR,
	DROPPED_COP_ALLOC_FAILED,
	CRYPTO_OP_FAILED,
	CRYPTO_OP_ASSOC_FAILED,
	CRYPTO_OP_PREPARE_FAILED,
	DROPPED_ESP_IP_FRAG,
	ESP_NOT_IN_FIRST_SEG,
	INVALID_CIPHERTEXT_LEN,
	ESP_TAIL_TRIM_FAILED,
	ESP_INVALID_NXT_HDR,
	INVALID_IPSEC_MODE,
	ESP_ETH_HDR_FIXUP_FAILED,
	ESP_OUT_HDR_PARSE6_FAILED,
	ESP_HDR_PREPEND_FAILED,
	ESP_TAIL_APPEND_FAILED,
	CRYPTO_CHAIN_INIT_FAILED,
	CRYPTO_AUTH_OP_FAILED,
	CRYPTO_CIPHER_OP_FAILED,
	CRYPTO_DIGEST_OP_FAILED,
	CRYPTO_DIGEST_CB_FAILED,
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
	/*
	 * total policy counts indicate the number
	 * of policies added to NPF prior to any commit
	 * occurring
	 */
	uint32_t crypto_total_ipv4_policies;
	uint32_t crypto_total_ipv6_policies;
	/*
	 * live policy counts indicate the number
	 * of policies active after the NPF commit is done
	 */
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
			       struct crypto_session *ctx,
			       bool pending);
int crypto_allocate_pmd(enum crypto_xfrm xfrm,
			enum rte_crypto_cipher_algorithm cipher_algo,
			enum rte_crypto_aead_algorithm aead_algo,
			bool *setup_openssl);
struct rte_ring *crypto_pmd_get_q(int dev_id, enum crypto_xfrm xfrm);
typedef bool (*crypto_pmd_walker_cb)(int pmd_dev_id, enum crypto_xfrm,
				     struct rte_ring *,
				     uint64_t *bytes,
				     uint32_t *packets);
unsigned int crypto_pmd_walk_per_xfrm(struct cds_list_head *pmd_head,
					      crypto_pmd_walker_cb cb);
void crypto_pmd_mod_pending_del(int pmd_dev_id, enum crypto_xfrm xfrm,
				bool inc);
void crypto_pmd_dec_pending_del(int pmd_dev_id, enum crypto_xfrm xfrm);
struct crypto_vrf_ctx *crypto_vrf_find(vrfid_t vrfid);
struct crypto_vrf_ctx *crypto_vrf_find_external(vrfid_t vrfid);
struct crypto_vrf_ctx *crypto_vrf_get(vrfid_t vrfid);
void crypto_vrf_check_remove(struct crypto_vrf_ctx *vrf_ctx);
struct ifnet *crypto_policy_feat_attach_by_reqid(uint32_t reqid);

/*
 * Per packet crypto context. This carries information
 * from the policy lookup in the forwarding thread that
 * is needed for the SA lookup in the crypto thread.
 */
struct crypto_pkt_ctx {
	/*
	 * The fields are ordered to minimize holes and
	 * place as much critical data as possible in the
	 * first cache line
	 */
	struct rte_mbuf *mbuf;
	uint32_t reqid;
	uint32_t spi;
	void *l3hdr;
	struct ifnet *in_ifp;
	struct ifnet *nxt_ifp;
	uint16_t out_ethertype;
	int8_t   status;
	uint8_t  udp_len;
	uint8_t  esp_len;
	uint8_t  icv_len;
	uint8_t  orig_family;
	uint8_t  family;
	struct sadb_sa *sa;
	struct ifnet *vti_ifp;

	/* --- cacheline 1 boundary (64 bytes) --- */

	uint16_t iphlen;
	uint16_t base_len;
	uint16_t ciphertext_len;
	uint16_t plaintext_size;
	uint16_t plaintext_size_orig;
	uint16_t prev_off;
	uint16_t head_trim;
	uint16_t out_hdr_len;
	uint8_t  action;
	uint8_t  in_ifp_port;
	uint16_t direction;
	/* bytes encrypted/decrypted */
	uint32_t bytes;
	unsigned char *esp;
	unsigned char *iv;
	unsigned char *icv;
	char *hdr;
	char *tail;
	unsigned int counter_modify;
	xfrm_address_t dst; /* Only used for outbound traffic */
	vrfid_t vrfid;
};

/*
 * Move bad (unprocessed) mbufs beyond the good (processed) ones.
 * bad_idx[] contains the indexes of bad context pointers.
 */
static inline void
move_bad_mbufs(struct crypto_pkt_ctx *ctx_arr[], uint16_t count,
	       const uint16_t bad_idx[], uint16_t bad_count)
{
	uint16_t i, j, k;
	struct crypto_pkt_ctx *tmp_ctx_arr[bad_count];

	if (likely(!bad_count))
		return;

	j = 0;
	k = 0;

	/* copy bad ones into a temp place */
	for (i = 0; i < count; i++) {
		if (j != bad_count && i == bad_idx[j])
			tmp_ctx_arr[j++] = ctx_arr[i];
		else
			ctx_arr[k++] = ctx_arr[i];
	}

	/* copy bad ones after the good ones */
	for (i = 0; i != bad_count; i++)
		ctx_arr[k + i] = tmp_ctx_arr[i];
}

#define CRYPTO_PREFETCH_LOOKAHEAD 10

static inline
void crypto_prefetch_ctx(struct crypto_pkt_ctx *ctx_arr[], uint16_t count,
			 uint16_t cur)
{
	uint16_t i, j;

	if (likely(cur % CRYPTO_PREFETCH_LOOKAHEAD))
		return;

	i = cur + CRYPTO_PREFETCH_LOOKAHEAD;
	j = cur;
	for (; j < count && j < i; j++)
		rte_prefetch0(ctx_arr[j]);
}

static inline
void crypto_prefetch_ctx_data(struct crypto_pkt_ctx *ctx_arr[], uint16_t count,
			      uint16_t cur)
{
	uint16_t i, j;

	if (likely(cur % CRYPTO_PREFETCH_LOOKAHEAD))
		return;

	i = cur + CRYPTO_PREFETCH_LOOKAHEAD;
	j = cur;
	for (; j < count && j < i; j++) {
		rte_prefetch0(ctx_arr[j]->mbuf);
		rte_prefetch0(ctx_arr[j]->sa);
	}
}

static inline
void crypto_prefetch_mbuf_data(struct crypto_pkt_ctx *ctx_arr[], uint16_t count,
			       uint16_t cur)
{
	uint16_t i, j;

	if (likely(cur % CRYPTO_PREFETCH_LOOKAHEAD))
		return;

	i = cur + CRYPTO_PREFETCH_LOOKAHEAD;
	j = cur + 1;
	for (; j < count && j < i; j++)
		rte_prefetch0(ctx_arr[j]->mbuf->cacheline1);
}

/*
 * Fetch data for entire burst into L2 cache
 * This results in a significant increase in throughput
 * with multiple cores due to a reduction in memory
 * contention
 */
static inline
void crypto_prefetch_mbuf_payload(struct rte_mbuf *m)
{
	uint16_t offset = 0;

	for (offset = 0; offset < rte_pktmbuf_data_len(m);
	     offset += RTE_CACHE_LINE_SIZE)
		rte_prefetch1(rte_pktmbuf_mtod_offset(m, void *,
						      offset));
}

void crypto_save_iv(uint16_t idx, const char iv[], uint16_t length);
void crypto_get_iv(uint16_t idx, char iv[], uint16_t length);

#endif /* CRYPTO_INTERNAL_H */
