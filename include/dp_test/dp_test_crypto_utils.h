/*-
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
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

#include "dp_test/dp_test_crypto_lib.h"

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
					     uint16_t id, uint8_t hlim,
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
	uint32_t rule_no;
};

void _dp_test_crypto_create_policy(const char *file, int line,
				   const struct dp_test_crypto_policy *policy,
				   bool verify, bool update, bool commit);
void _dp_test_crypto_delete_policy(const char *file, int line,
				   const struct dp_test_crypto_policy *policy,
				   bool verify, bool commit);
void _dp_test_crypto_check_policy_count(vrfid_t vrfid,
					unsigned int num_policies, int af,
					const char *file, int line);

#define dp_test_crypto_create_policy(_policy)			\
	_dp_test_crypto_create_policy(__FILE__, __LINE__, _policy, true, false, \
				      true)

#define dp_test_crypto_create_policy_verify(_policy, _verify)  \
	_dp_test_crypto_create_policy(__FILE__, __LINE__, _policy, _verify, \
				      false, true)

#define dp_test_crypto_create_policy_commit(_policy, _commit)  \
	_dp_test_crypto_create_policy(__FILE__, __LINE__, _policy, false, \
				      false, _commit)

#define dp_test_crypto_update_policy(_policy)		\
	_dp_test_crypto_create_policy(__FILE__, __LINE__, _policy, true, true, \
				      true)

#define dp_test_crypto_delete_policy(_policy)		\
	_dp_test_crypto_delete_policy(__FILE__, __LINE__, _policy, true, true)

#define dp_test_crypto_delete_policy_verify(_policy, _verify)		\
	_dp_test_crypto_delete_policy(__FILE__, __LINE__, _policy, _verify, \
				      true)

#define dp_test_crypto_delete_policy_commit(_policy, _commit)		\
	_dp_test_crypto_delete_policy(__FILE__, __LINE__, _policy, false, \
				      _commit)

#define dp_test_crypto_check_policy_count(vrfid, num_policies, af)	      \
	_dp_test_crypto_check_policy_count(vrfid, num_policies, af, __FILE__, \
					   __LINE__)

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
void _dp_test_crypto_delete_sa_verify(const char *file, int line,
				      const struct dp_test_crypto_sa *sa,
				      bool verify);
void _dp_test_crypto_expire_sa(const char *file, int line,
			       const struct dp_test_crypto_sa *sa, bool hard);
void _dp_test_crypto_get_sa(const char *file, int line,
			    const struct dp_test_crypto_sa *sa);

#define dp_test_crypto_create_sa(_sa)					\
	_dp_test_crypto_create_sa(__FILE__, __func__, __LINE__, _sa, true)
#define dp_test_crypto_create_sa_verify(_sa, verify)	\
	_dp_test_crypto_create_sa(__FILE__, __func__, __LINE__, _sa, verify)

#define dp_test_crypto_delete_sa(_sa)		\
	_dp_test_crypto_delete_sa_verify(__FILE__, __LINE__, _sa, true)
#define dp_test_crypto_delete_sa_verify(_sa, verify)		\
	_dp_test_crypto_delete_sa_verify(__FILE__, __LINE__, _sa, verify)

#define dp_test_crypto_get_sa(_sa)		\
	_dp_test_crypto_get_sa(__FILE__, __LINE__, _sa)

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

enum dp_test_crypto_check_resp_type {
	DP_TEST_CHECK_CRYPTO_SEQ,
	DP_TEST_CHECK_CRYPTO_SA_STATS,
};

void
_dp_test_crypto_check_xfrm_resp(const char *file, int line,
				enum dp_test_crypto_check_resp_type type,
				uint64_t exp_bytes, uint64_t exp_packets,
				bool match);
#define dp_test_crypto_check_xfrm_acks()	\
	_dp_test_crypto_check_xfrm_resp(__FILE__, __LINE__,	\
					DP_TEST_CHECK_CRYPTO_SEQ,	\
					0, 0, true)

#define dp_test_crypto_check_xfrm_sa_cntrs(_pkts, _bytes, _match)	\
	_dp_test_crypto_check_xfrm_resp(__FILE__, __LINE__,		\
					DP_TEST_CHECK_CRYPTO_SA_STATS,	\
					_pkts, _bytes, _match)

void _dp_test_xfrm_set_nack(uint32_t err_count);

#define dp_test_crypto_xfrm_set_nack(count)	\
	_dp_test_xfrm_set_nack(count)

void  _dp_test_crypto_flush(void);
#define dp_test_crypto_flush()			\
	_dp_test_crypto_flush()

void  _dp_test_crypto_commit(void);
#define dp_test_crypto_commit()		\
	_dp_test_crypto_commit()

void _dp_test_xfrm_poison_sa_stats(void);
#define dp_test_xfrm_poison_sa_stats()	\
	_dp_test_xfrm_poison_sa_stats()

/*
 * Note that the config and associated functions below is to set-up an IPSec
 * site-to-site setup as shown below, with UUT being the device being tested.
 *
 *                       +---------+          +---------+
 * +------------+        |         |          |         |         +----------+
 * |            |        |         |          |         |         |          |
 * | Client     +--------+   UUT   +----------+  PEER   +---------+ Client   |
 * |  local     |        |         |          |         |         |  remote  |
 * |            |        |         |          |         |         |          |
 * +------------+        |         |          |         |         +----------+
 *                       +---------+          +---------+
 *
 *     WEST <<<<<<<<<<<<<<         >>>>>>>>>>>>> EAST
 */

struct dp_test_s2s_config {
	vrfid_t vrfid;
	enum dp_test_crypo_cipher_algo cipher_algo;
	enum dp_test_crypo_auth_algo auth_algo;
	int af;		/* AF_INET or AF_INET6 */
	char *iface1;
	char *iface1_ip_with_mask;
	char *client_local_ip;
	char *network_local_ip_with_mask;
	char *network_local_ip;
	uint32_t network_local_mask;
	char *client_local_mac;
	char *port_west_ip;
	char *iface2;
	char *iface2_ip_with_mask;
	char *peer_ip;
	char *peer_mac;
	char *network_east_ip_with_mask;
	char *port_east_ip;
	char *network_remote;
	char *network_remote_ip_with_mask;
	char *network_remote_ip;
	uint32_t network_remote_mask;
	char *client_remote_ip;
	char *iface_vfp;
	char *iface_vfp_ip;
	bool vfp_out_of_order;
	uint8_t nipols;
	struct dp_test_crypto_policy *ipolicy;
	struct dp_test_crypto_policy def_ipolicy;
	uint8_t nopols;
	struct dp_test_crypto_policy *opolicy;
	struct dp_test_crypto_policy def_opolicy;
	unsigned int mode;
	enum vfp_presence with_vfp;
	enum vrf_and_xfrm_order out_of_order;
	struct dp_test_crypto_sa input_sa;
	struct dp_test_crypto_sa output_sa;
};

void _dp_test_s2s_add_vfp_and_bind(struct dp_test_s2s_config *conf,
				   const char *file, const char *func,
				   int line);

void _dp_test_s2s_del_vfp_and_unbind(struct dp_test_s2s_config *conf,
				     const char *file, const char *func,
				     int line);

#define dp_test_s2s_setup_interfaces(conf) \
	_dp_test_s2s_setup_interfaces(conf, __FILE__, __func__, __LINE__)

void _dp_test_s2s_setup_interfaces(struct dp_test_s2s_config *conf,
				   const char *file, const char *func,
				   int line);

#define dp_test_s2s_setup_interfaces_finish(conf) \
	_dp_test_s2s_setup_interfaces_finish(conf, __FILE__, __func__, __LINE__)

void _dp_test_s2s_setup_interfaces_finish(struct dp_test_s2s_config *conf,
					  const char *file, const char *func,
					  int line);

void _dp_test_s2s_teardown_interfaces(struct dp_test_s2s_config *conf,
				      bool leave_vrf, const char *file,
				      const char *func, int line);

#define dp_test_s2s_teardown_interfaces(conf) \
	_dp_test_s2s_teardown_interfaces(conf, false, __FILE__, __func__, \
					 __LINE__)

#define dp_test_s2s_teardown_interfaces_leave_vrf(conf) \
	_dp_test_s2s_teardown_interfaces(conf, true, __FILE__, __func__, \
					 __LINE__)

void dp_test_s2s_common_setup(struct dp_test_s2s_config *conf);

void dp_test_s2s_common_teardown(struct dp_test_s2s_config *conf);

#endif /*_DP_TEST_CRYPTO_UTILS_H_ */
