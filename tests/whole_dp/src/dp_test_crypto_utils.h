/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Site-to-Site crypto tests
 */
#ifndef _DP_TEST_CRYPTO_UTILS_H_
#define _DP_TEST_CRYPTO_UTILS_H_

#include <stdint.h>
#include <stdbool.h>

#include <linux/xfrm.h>
#include <netinet/udp.h>
#include "vrf.h"

struct dp_test_expected;

struct rte_mbuf *dp_test_create_esp_ipv4_pak(const char *saddr, const char *daddr,
					     int n, int *len, const char *payload,
					     uint32_t spi, uint32_t seq_no,
					     uint16_t id, uint8_t ttl,
					     struct udphdr *udp,
					     struct iphdr *transport);
struct rte_mbuf *dp_test_create_esp_ipv6_pak(const char *saddr,
					     const char *daddr,
					     int n, int *len,
					     const char *payload,
					     uint32_t spi, uint32_t seq_no,
					     uint16_t id, uint8_t ttl,
					     struct ip6_hdr *transport);

struct dp_test_crypto_policy {
	const char *d_prefix;
	const char *s_prefix;
	int proto;
	const char *dst;
	int family;
	int dst_family;
	int dir;
	uint32_t priority;
	uint32_t reqid;
	uint32_t mark;
	uint8_t  action;
	vrfid_t vrfid;
	bool	passthrough;
};

void _dp_test_crypto_create_policy(const char *file, int line,
				   const struct dp_test_crypto_policy *policy,
				   bool verify);
void _dp_test_crypto_delete_policy(const char *file, int line,
				   const struct dp_test_crypto_policy *policy);
void _dp_test_crypto_update_policy(const char *file, int line,
				   const struct dp_test_crypto_policy *policy);

#define dp_test_crypto_create_policy(_policy)			\
	_dp_test_crypto_create_policy(__FILE__, __LINE__, _policy, true)
#define dp_test_crypto_create_policy_verify(_policy, _verify)	\
	_dp_test_crypto_create_policy(__FILE__, __LINE__, _policy, _verify)

#define dp_test_crypto_update_policy(_policy)		\
	_dp_test_crypto_create_policy(__FILE__, __LINE__, _policy, true)

#define dp_test_crypto_delete_policy(_policy)		\
	_dp_test_crypto_delete_policy(__FILE__, __LINE__, _policy)

/*
 * Cipher algorithms supported by test suite.
 */
enum dp_test_crypo_cipher_algo {
	CRYPTO_CIPHER_AES_CBC = 0,
	CRYPTO_CIPHER_NULL,
	CRYPTO_CIPHER_AES128GCM,
};

/*
 * Authentication algorithms supported by test suite.
 */
enum dp_test_crypo_auth_algo {
	CRYPTO_AUTH_HMAC_SHA1 = 0,
	CRYPTO_AUTH_HMAC_XCBC,
	CRYPTO_AUTH_NULL,
};

/*
 * This structure is used to define Crypto SAs that
 * are to be created by the crypto test infrastructure.
 * The cipher_key, auth_key and auth_trunc_key are optional.
 * If they are not specified a default key and key_len are used.
 */
struct dp_test_crypto_sa {
	enum dp_test_crypo_cipher_algo cipher_algo;
	const unsigned char *cipher_key;
	uint32_t cipher_key_len;
	enum dp_test_crypo_auth_algo auth_algo;
	const unsigned char *auth_key;
	uint32_t auth_key_len;
	const unsigned char *auth_trunc_key;
	uint32_t auth_trunc_key_len;
	uint32_t spi;
	const char *d_addr;
	const char *s_addr;
	int family;
	int mode;
	int reqid;
	int mark;
	struct xfrm_encap_tmpl *encap_tmpl;
	vrfid_t vrfid;
	uint32_t flags;
	uint32_t extra_flags;
};

#define AES128GM_KEY_LEN 160

void _dp_test_crypto_create_sa(const char *file, const char *func, int line,
			       const struct dp_test_crypto_sa *sa, bool verify);
void _dp_test_crypto_delete_sa(const char *file, int line,
			       const struct dp_test_crypto_sa *sa);
void _dp_test_crypto_expire_sa(const char *file, int line,
			       const struct dp_test_crypto_sa *sa, bool hard);

#define dp_test_crypto_create_sa(_sa)		\
	_dp_test_crypto_create_sa(__FILE__, __func__, __LINE__, _sa, true)
#define dp_test_crypto_create_sa_verify(_sa, verify)	\
	_dp_test_crypto_create_sa(__FILE__, __func__, __LINE__, _sa, verify)

#define dp_test_crypto_delete_sa(_sa)		\
	_dp_test_crypto_delete_sa(__FILE__, __LINE__, _sa)

#define dp_test_crypto_expire_sa(_sa, _hard)	\
	_dp_test_crypto_expire_sa(__FILE__, __LINE__, _sa, _hard)

void _dp_test_crypto_check_sad_packets(
	vrfid_t vrfid, uint64_t packets, uint64_t bytes,
	const char *file, int line);

void _dp_test_crypto_check_sa_count(
	vrfid_t vrfid, unsigned int num_sas,
	const char *file, int line);

#define dp_test_crypto_check_sad_packets(vrfid, packets, bytes)		\
	_dp_test_crypto_check_sad_packets(vrfid, packets, bytes,	\
					  __FILE__, __LINE__)
#define dp_test_crypto_check_sa_count(vrfid, num_sas) \
	_dp_test_crypto_check_sa_count(vrfid, num_sas, __FILE__,	\
				       __LINE__)

#define wait_for_policy(policy, check_present)				\
	_wait_for_policy(policy, check_present, __FILE__, __LINE__)
void _wait_for_policy(const struct dp_test_crypto_policy *policy,
		     bool check_present, const char *file, int line);

#define wait_for_sa(sa, check_present) \
	_wait_for_sa(sa, check_present, __FILE__, __LINE__)
void _wait_for_sa(const struct dp_test_crypto_sa *sa,
		  bool check_present, const char *file, int line);

struct dp_test_expected *
generate_exp_unreachable(struct rte_mbuf *input_pkt, int payload_len,
			 const char *source_ip, const char *dest_ip,
			 const char *oif, const char *dmac);

struct dp_test_expected *
generate_exp_unreachable6(struct rte_mbuf *input_pkt, int payload_len,
			 const char *source_ip, const char *dest_ip,
			 const char *oif, const char *dmac);

#endif /*_DP_TEST_CRYPTO_UTILS_H_ */
