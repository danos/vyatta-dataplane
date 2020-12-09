/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Crypto testing utilities
 */
#include <string.h>
#include <unistd.h>
#include <netinet/udp.h>
#include <netinet6/ip6_funcs.h>
#include <execinfo.h>

#include <rte_mbuf.h>

#include "pktmbuf_internal.h"
#include "ip_funcs.h"
#include "util.h"
#include "crypto/crypto.h"

#include "dp_test_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test/dp_test_macros.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_crypto_utils.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test/dp_test_cmd_check.h"
#include "dp_test_crypto_lib.h"
#include "dp_test_json_utils.h"
#include "dp_test_xfrm_server.h"

static const unsigned char default_cipher_key[] = {
	0x1c, 0x53, 0xfa, 0xd5, 0xb5, 0x23, 0xb3, 0xe1,
	0x79, 0xd3, 0xc7, 0xc2, 0xe8, 0x4a, 0x19, 0x37,
	0x74, 0x29, 0xcb, 0xcc, 0xc1, 0x2d, 0xa0, 0xb8,
	0x23, 0xdd, 0xdc, 0x18, 0x96, 0xf9, 0x0e, 0x40
};

static const unsigned  char default_auth_key[] = {
	0x75, 0x6e, 0x75, 0xd7, 0x50, 0xd0, 0xf8, 0x1e,
	0x99, 0xe7, 0x78, 0xcb, 0x60, 0xf4, 0xdb, 0x1c,
	0x06, 0x00, 0x41, 0x00
};

static const unsigned char default_auth_trunc_key[] = {
	0x0a, 0x88, 0x0c, 0x9c, 0x75, 0x6e, 0x75, 0xd7,
	0x50, 0xd0, 0xf8, 0x1e, 0x99, 0xe7, 0x78, 0xcb,
	0x60, 0xf4, 0xdb, 0x1c
};

static struct xfrm_algo *cipher_algo_alloc(const char *alg_name,
					   const unsigned char *key,
					   unsigned int key_len_in_bits)
{
	unsigned int key_len_in_bytes = key_len_in_bits / 8;
	struct xfrm_algo *cipher_algo;

	if (key_len_in_bits != 128 && key_len_in_bits != 256 &&
	    key_len_in_bits == AES128GM_KEY_LEN &&
	    strcmp(alg_name, "eNULL") != 0)
		dp_test_assert_internal(0);

	cipher_algo = malloc(sizeof(*cipher_algo) + key_len_in_bytes);
	dp_test_assert_internal(cipher_algo);

	strncpy(&cipher_algo->alg_name[0], alg_name,
		sizeof(cipher_algo->alg_name));
	memcpy(&cipher_algo->alg_key, key, key_len_in_bytes);
	cipher_algo->alg_key_len = key_len_in_bits;

	return cipher_algo;
}

static struct xfrm_algo_aead *algo_aead_alloc(const char *alg_name,
					      const unsigned char *key,
					      unsigned int key_len_in_bits)
{
	unsigned int key_len_in_bytes = key_len_in_bits / 8;
	struct xfrm_algo_aead *aead_algo;

	if (key_len_in_bits != AES128GM_KEY_LEN ||
	    strcmp(alg_name, "rfc4106(gcm(aes))") != 0)
		dp_test_assert_internal(0);

	aead_algo = malloc(sizeof(*aead_algo) + key_len_in_bytes);
	dp_test_assert_internal(aead_algo);

	strncpy(&aead_algo->alg_name[0], alg_name,
		sizeof(aead_algo->alg_name));
	memcpy(&aead_algo->alg_key, key, key_len_in_bytes);
	aead_algo->alg_key_len = key_len_in_bits;
	aead_algo->alg_icv_len = 128;
	return aead_algo;
}

static struct xfrm_algo_auth *auth_algo_alloc(const char *alg_name,
					      const unsigned char *key,
					      unsigned int key_len_in_bits)
{
	unsigned int key_len_in_bytes = key_len_in_bits / 8;
	struct xfrm_algo_auth *algo_auth;

	/* Only 160 bit keys are supported */
	if (key_len_in_bits != 160 && strcmp(alg_name, "aNULL") != 0)
		dp_test_assert_internal(0);

	algo_auth = malloc(sizeof(*algo_auth) + key_len_in_bytes);
	dp_test_assert_internal(algo_auth);

	strncpy(&algo_auth->alg_name[0], alg_name,
		sizeof(algo_auth->alg_name));

	memcpy(&algo_auth->alg_key, key, key_len_in_bytes);
	algo_auth->alg_key_len = key_len_in_bits;
	algo_auth->alg_trunc_len = 0;

	return algo_auth;
}

/**
 * Initialize ESP header.  Assumes l2 and l3 headers already setup.
 *
 * @param  m [in]  Pointer to packet mbuf
 * @return Pointer to ESP header if successful, else NULL
 */
static struct ip_esp_hdr *
dp_test_pktmbuf_esp_init(struct rte_mbuf *m, uint16_t udphdrlen,
			 uint32_t spi, uint32_t seq_no)
{
	struct ip_esp_hdr *esp;
	uint16_t hlen;

	assert(m->l2_len);
	assert(m->l3_len);
	hlen = m->l2_len + m->l3_len + udphdrlen +  sizeof(*esp);

	/* Is there room for ESP hdr in first mbuf? */
	if (hlen > m->data_len) {
		printf("Not enough space for ESP header");
		printf("Required >= %d, actual %d\n", hlen, m->data_len);
		return NULL;
	}

	esp = dp_pktmbuf_mtol4(m, struct ip_esp_hdr *);
	esp = (struct ip_esp_hdr *)((unsigned char *)esp + udphdrlen);
	memset(esp, 0, sizeof(*esp));
	esp->spi = spi;
	esp->seq_no = htonl(seq_no);
	return esp;
}

static struct iphdr *
dp_test_create_transport_hdr(struct rte_mbuf *m, struct iphdr *iphdr)
{
	struct iphdr *ip;

	m->l3_len = sizeof(*iphdr);
	ip = dp_pktmbuf_mtol3(m, struct iphdr *);

	memmove(ip, iphdr, sizeof(*iphdr));

	return ip;
}

/**
 * Create and initialise an IPv4 ESP packet
 *
 * @param saddr   [in] Source address string, e.g. "10.0.1.0"
 * @param daddr   [in] Dest address string
 * @param n       [in] Number of mbufs
 * @param len     [in] Array of 'n' per-mbuf payload lengths
 * @param payload [in] Payload to write to the packet.	May be NULL, in
 *		       which case a test pattern is used.
 * @param spi     [in] A 32-bit cookie that might match an SA
 * @param seq_no  [in] A 32 bit sequence number
 *
 * @return pak        Pointer to mbuf if successful, else NULL
 */
struct rte_mbuf *
dp_test_create_esp_ipv4_pak(const char *saddr, const char *daddr,
			    int n, int *len, const char *payload,
			    uint32_t spi, uint32_t seq_no,
			    uint16_t id, uint8_t ttl,
			    struct udphdr *udphdr,
			    struct iphdr *transport_iphdr)
{
	struct rte_mbuf *pak;
	struct ip_esp_hdr *esp;
	struct iphdr *ip;
	uint16_t hlen, udphdrlen;
	uint8_t protocol;
	struct udphdr *udp;

	udphdrlen = udphdr ? sizeof(struct udphdr) : 0;
	protocol = udphdr ? IPPROTO_UDP : IPPROTO_ESP;
	/* Create mbuf chain */
	hlen = sizeof(*ip) + udphdrlen + sizeof(*esp);
	pak = dp_test_create_mbuf_chain(n, len, hlen);
	if (!pak)
		return NULL;

	if (!dp_test_pktmbuf_eth_init(pak, NULL, NULL, RTE_ETHER_TYPE_IPV4)) {
		rte_pktmbuf_free(pak);
		return NULL;
	}
	if (transport_iphdr)
		ip = dp_test_create_transport_hdr(pak, transport_iphdr);
	else
		ip = dp_test_pktmbuf_ip_init(pak, saddr, daddr, protocol);
	if (!ip) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	if (transport_iphdr) {
		ip->protocol = protocol;
		ip->tot_len = htons(hlen + *len);
	} else {
		ip->id = id;
		ip->ttl = ttl;
	}

	/* recalculation checksum */
	ip->check = 0;
	ip->check = rte_ipv4_cksum((const struct rte_ipv4_hdr *)ip);

	/* Payload offset and length */
	uint32_t poff = pak->l2_len + pak->l3_len + udphdrlen + sizeof(*esp);
	uint32_t plen = pak->pkt_len - poff;

	if (udphdr) {
		udp = (struct udphdr *)(++ip);
		udp->source = udphdr->source;
		udp->dest = udphdr->dest;
		udp->check = 0;
		udp->len = htons(udphdrlen + sizeof(*esp) + *len);
	}

	/* Write test pattern to mbuf payload */
	if (dp_test_pktmbuf_payload_init(pak, poff, payload, plen) == 0) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	esp = dp_test_pktmbuf_esp_init(pak, udphdrlen, spi, seq_no);
	if (!esp) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	return pak;
}

static struct ip6_hdr *
dp_test_create_transport_hdr6(struct rte_mbuf *m, struct ip6_hdr *ip6_hdr)
{
	struct ip6_hdr *ip6;

	m->l3_len = sizeof(*ip6_hdr);
	ip6 = dp_pktmbuf_mtol3(m, struct ip6_hdr *);

	memmove(ip6, ip6_hdr, sizeof(*ip6_hdr));

	return ip6;
}

/**
 * Create and initialise an IPv6 ESP packet
 *
 * @param saddr   [in] Source address string, e.g. "2001:1::"
 * @param daddr   [in] Dest address string
 * @param n       [in] Number of mbufs
 * @param len     [in] Array of 'n' per-mbuf payload lengths
 * @param payload [in] Payload to write to the packet.	May be NULL, in
 *		       which case a test pattern is used.
 * @param spi     [in] A 32-bit cookie that might match an SA
 * @param seq_no  [in] A 32 bit sequence number
 *
 * @return pak        Pointer to mbuf if successful, else NULL
 */
struct rte_mbuf *
dp_test_create_esp_ipv6_pak(const char *saddr, const char *daddr,
			    int n, int *len, const char *payload,
			    uint32_t spi, uint32_t seq_no,
			    uint16_t id,
			    uint8_t hlim,
			    struct ip6_hdr *transport)
{
	struct rte_mbuf *pak;
	struct ip_esp_hdr *esp;
	struct ip6_hdr *ip6;
	uint16_t hlen;

	/* Create mbuf chain */
	hlen = sizeof(*ip6) + sizeof(*esp);
	pak = dp_test_create_mbuf_chain(n, len, hlen);
	if (!pak)
		return NULL;

	if (!dp_test_pktmbuf_eth_init(pak, NULL, NULL, RTE_ETHER_TYPE_IPV6)) {
		rte_pktmbuf_free(pak);
		return NULL;
	}
	if (transport)
		ip6 = dp_test_create_transport_hdr6(pak, transport);
	else
		ip6 = dp_test_pktmbuf_ip6_init(pak, saddr, daddr, IPPROTO_ESP);
	if (!ip6) {
		rte_pktmbuf_free(pak);
		return NULL;
	}


	/* Payload offset and length */
	uint32_t poff = pak->l2_len + pak->l3_len + sizeof(*esp);
	uint32_t plen = pak->pkt_len - poff;

	if (transport) {
		ip6->ip6_nxt = IPPROTO_ESP;
		ip6->ip6_plen = htons(plen + sizeof(*esp));
	} else {
		ip6->ip6_hlim = hlim;
	}

	/* Write test pattern to mbuf payload */
	if (dp_test_pktmbuf_payload_init(pak, poff, payload, plen) == 0) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	esp = dp_test_pktmbuf_esp_init(pak, 0, spi, seq_no);
	if (!esp) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	return pak;
}

/*
 * build_xfrm_selector()
 *
 * This function populates the supplied struct xfrm_selector
 * with the destination and source prefix passed to it in
 * string form.
 */
static void build_xfrm_selector(struct xfrm_selector *sel,
				const char *d_prefix,
				const char *s_prefix,
				uint8_t proto,
				int family)
{
	memset(sel, 0, sizeof(*sel));

	if (dp_test_prefix_str_to_xfrm_addr(d_prefix, &sel->daddr,
					    &sel->prefixlen_d, family))
		dp_test_assert_internal(0);

	if (dp_test_prefix_str_to_xfrm_addr(s_prefix, &sel->saddr,
					    &sel->prefixlen_s, family))
		dp_test_assert_internal(0);

	sel->family = family;
	sel->proto = proto;
}

static void wait_for_npf_policy(const struct dp_test_crypto_policy *policy,
				bool check_present, uint32_t vrf_id,
				const char *file, int line)
{
	json_object *expected_json;
	char proto_str[100];
	char vrf_str[100];
	static const char template[] =
	  "{"
	      "\"config\": [{"
		  "\"attach_type\": \"vrf\","
		  "\"attach_point\": \"%d\","
		  "\"rulesets\": [{"
		      "\"ruleset_type\": \"ipsec\","
		      "\"groups\": [{"
			  "\"class\": \"ipsec\","
			  "\"name\": \"%s\","
			  "\"direction\": \"out\","
			  "\"rules\": {"
			      "\""__JSON_ANY_KEY_VAL__"\": {"
				  "\"action\": \"%s \","
				  "\"match\": \"%sfrom %s to %s *\","
			      "}"
			  "}"
		      "}]"
		  "}]"
	      "}]"
	   "}";

	if (policy->proto)
		snprintf(proto_str, 100, "proto-final %d ", policy->proto);

	snprintf(vrf_str, 100, "out-%d", vrf_id);

	char const *npf_action =
		(policy->action == XFRM_POLICY_ALLOW) ? "pass" : "block";
	expected_json = dp_test_json_create(template,
					    vrf_id,
					    vrf_str,
					    npf_action,
					    policy->proto ? proto_str : "",
					    policy->s_prefix,
					    policy->d_prefix);

	_dp_test_check_json_state("npf-op show all: ipsec",
				  expected_json, NULL,
				  DP_TEST_JSON_CHECK_SUBSET,
				  !check_present,
				  file, "", line);

	json_object_put(expected_json);
}

static uint32_t poll_cnt;

static int _dp_test_crypto_poll_xfrm_acks(zloop_t *loop, int poller, void *arg)
{
	bool *match = (bool *)arg;

	poll_cnt--;

	if (xfrm_seq == xfrm_seq_received)
		*match = true;

	/* return -1 to stop if we got what we want or run out of retries */
	return (*match || poll_cnt == 0) ? -1 : 0;
}

static void _dp_test_crypto_check_xfrm_acks(const char *file, int line)
{

	int timer;
	zloop_t *loop = zloop_new();
	bool match = false;

	poll_cnt = DP_TEST_POLL_COUNT;
	timer = zloop_timer(loop, DP_TEST_POLL_INTERVAL, 0,
			    _dp_test_crypto_poll_xfrm_acks,
			    &match);
	dp_test_assert_internal(timer >= 0);

	/* Check the number of xfrm messages sent equal the number of acks
	 * received.
	 */
	zloop_start(loop);
	zloop_destroy(&loop);

	if (!match)
		_dp_test_fail(file, line, "Missing acks Tx %d Rx %d:\n",
			      xfrm_seq, xfrm_seq_received);
}

/*
 * wait_for_policy()
 *
 * Wait for a the specified policy to be created in the dataplane.
 */
void _wait_for_policy(const struct dp_test_crypto_policy *policy,
		      bool check_present, const char *file, int line)
{
	json_object *expected_json;
	const char *peer_str, *dir_str, *action_str;
	char reqid_str[64], cmd_str[100];
	static const char template[] = "{"
					   "\"ipsec_policies\": {"
					       "\"policies\": [{"
						   "\"dst\": \"%s\","
						   "\"src\": \"%s\","
						   "\"proto\": %d,"
						   "\"priority\": %d,%s"
						   "\"peer\": \"%s\","
						   "\"direction\": \"%s\","
						   "\"action\": \"%s\","
					       " }]"
				       "}}";
	uint32_t vrf_id = policy->vrfid;

	if (policy->dir == XFRM_POLICY_OUT) {
		dir_str = "encryption-out";
		if (policy->action != XFRM_POLICY_BLOCK) {
			peer_str = policy->dst;
			snprintf(reqid_str, sizeof(reqid_str),
				 " \"reqid\": %u, ", policy->reqid);
			action_str = "allow";
		} else {
			/*
			 * For input policies the peer address is returned
			 * as the empty string and the req_id is not
			 * returned at all.
			 */
			peer_str = "blocked";
			reqid_str[0] = '\0';
			action_str = "block";
		}
	} else {
		dir_str = "in-rp-check";
		peer_str = "local";
		reqid_str[0] = '\0';
		/*
		 * INPUT policies are always marked as BLOCK
		 */
		action_str = "allow-decrypted-traffic";
	}

	expected_json = dp_test_json_create(template,
					    policy->d_prefix,
					    policy->s_prefix,
					    policy->proto,
					    policy->priority,
					    reqid_str,
					    peer_str,
					    dir_str,
					    action_str);

	vrf_id = dp_test_translate_vrf_id(vrf_id);
	snprintf(cmd_str, sizeof(cmd_str),
		 "ipsec spd vrf_id %d", vrf_id);
	_dp_test_check_json_state(cmd_str,
				  expected_json, NULL,
				  DP_TEST_JSON_CHECK_SUBSET,
				  !check_present,
				  file, "", line);

	json_object_put(expected_json);

	if (policy->dir == XFRM_POLICY_OUT && !policy->mark)
		wait_for_npf_policy(policy, check_present, vrf_id, file, line);
}

/*
 * _dp_test_create_ipsec_policy()
 *
 * Create an IPsec policy in the dataplane
 */
void _dp_test_crypto_create_policy(const char *file, int line,
				   const struct dp_test_crypto_policy *policy,
				   bool verify)
{
	struct xfrm_selector sel;
	xfrm_address_t dst;

	build_xfrm_selector(&sel, policy->d_prefix, policy->s_prefix,
			    policy->proto, policy->family);

	if (dp_test_prefix_str_to_xfrm_addr(policy->dst, &dst,
					    NULL, policy->dst_family))
		dp_test_assert_internal(0);

	_dp_test_netlink_xfrm_policy(XFRM_MSG_NEWPOLICY,
				     &sel, &dst,
				     policy->dst_family,
				     policy->dir,
				     policy->priority,
				     policy->reqid,
				     policy->mark,
				     policy->action,
				     policy->vrfid,
					 policy->passthrough,
				     file, line);


	if (verify)
		_wait_for_policy(policy, true, file, line);
}

/*
 * _dp_test_delete_ipsec_policy()
 *
 * Delete an IPsec policy from the dataplane
 */
void _dp_test_crypto_delete_policy(const char *file, int line,
				   const struct dp_test_crypto_policy *policy,
				   bool verify)
{
	struct xfrm_selector sel;
	xfrm_address_t dst;

	build_xfrm_selector(&sel, policy->d_prefix, policy->s_prefix,
			    policy->proto, policy->family);

	if (dp_test_prefix_str_to_xfrm_addr(policy->dst, &dst,
					    NULL, policy->dst_family))
		dp_test_assert_internal(0);

	_dp_test_netlink_xfrm_policy(XFRM_MSG_DELPOLICY,
				     &sel, &dst,
				     policy->dst_family,
				     policy->dir,
				     policy->priority,
				     policy->reqid,
				     policy->mark,
				     policy->action,
				     policy->vrfid,
					 policy->passthrough,
				     file, line);

	if (verify)
		_wait_for_policy(policy, false, file, line);
}

void _dp_test_crypto_check_policy_count(vrfid_t vrfid,
					unsigned int num_policies, int af,
					const char *file, int line)
{
#define POLL_CNT 1000
#define POLL_INTERVAL 50
	char cmd_str[100];
	char exp_str[100];
	static const char template[] = "{"
					   "\"ipsec_policies\": {"
					       "\"vrf\": %d,"
					       "\"live_policy_count\": {"
						   "\"%s\": %d,"
					       " }"
				       "}}";
	json_object *jexp;

	vrfid = dp_test_translate_vrf_id(vrfid);

	snprintf(cmd_str, sizeof(cmd_str), "ipsec spd vrf_id %d brief", vrfid);
	snprintf(exp_str, sizeof(exp_str), template, vrfid,
		 af == AF_INET ? "ipv4" : "ipv6", num_policies);

	jexp = dp_test_json_create("%s", exp_str);
	dp_test_check_json_poll_state_interval(cmd_str, jexp,
					       DP_TEST_JSON_CHECK_SUBSET,
					       false, POLL_CNT, POLL_INTERVAL);
	json_object_put(jexp);

	dp_test_crypto_check_xfrm_acks();

}


/*
 * wait_for_sa()
 *
 * Wait for a the specified SA to be created in the dataplane.
 */
void _wait_for_sa(const struct dp_test_crypto_sa *sa,
		  bool check_present, const char *file, int line)
{
	json_object *expected_json;
	char spi_str[32], cmd_str[100];
	static const char template[] = "{"
					   "\"sas\": [{"
					       "\"spi\": \"%s\","
					       "\"dst\": \"%s\","
					       "\"src\": \"%s\","
					       "\"reqid\": %d,"
					   " }]"
				       "}";
	uint32_t vrf_id = sa->vrfid;

	snprintf(spi_str, sizeof(spi_str), "%08x", sa->spi);
	expected_json = dp_test_json_create(template,
					    spi_str,
					    sa->d_addr,
					    sa->s_addr,
					    sa->reqid);

	vrf_id = dp_test_translate_vrf_id(vrf_id);
	snprintf(cmd_str, sizeof(cmd_str),
		 "ipsec sad vrf_id %d", vrf_id);
	_dp_test_check_json_state(cmd_str,
				  expected_json, NULL,
				  DP_TEST_JSON_CHECK_SUBSET,
				  !check_present,
				  file, "", line);

	json_object_put(expected_json);
}

void _dp_test_crypto_create_sa(const char *file, const char *func, int line,
			       const struct dp_test_crypto_sa *sa,
			       bool verify)
{
	struct xfrm_algo_auth *algo_auth_trunc = NULL;
	struct xfrm_algo_auth *algo_auth = NULL;
	struct xfrm_algo *cipher_algo = NULL;
	struct xfrm_algo_aead *aead_algo = NULL;
	const unsigned char *auth_trunc_key = default_auth_trunc_key;
	const unsigned char *auth_key = default_auth_key;
	uint32_t auth_trunc_key_len;
	uint32_t auth_key_len;
	const unsigned char *cipher_key = default_cipher_key;
	uint32_t cipher_key_len;

	/*
	 * Use the auth and auth_trunc keys if supplied.
	 */
	if (sa->auth_key) {
		auth_key_len = sa->auth_key_len;
		auth_key = sa->auth_key;
	} else {
		auth_key_len = sizeof(default_auth_key) * 8;
		auth_key = default_auth_key;
	}

	if (sa->auth_trunc_key) {
		auth_trunc_key_len = sa->auth_trunc_key_len;
		auth_trunc_key = sa->auth_trunc_key;
	} else {
		auth_trunc_key_len = sizeof(default_auth_trunc_key) * 8;
		auth_trunc_key = default_auth_trunc_key;
	}

	switch (sa->auth_algo) {
	case CRYPTO_AUTH_HMAC_SHA1:
		algo_auth = auth_algo_alloc("hmac(sha1)",
					    auth_key, auth_key_len);
		algo_auth_trunc = auth_algo_alloc("hmac(sha1)",
						  auth_trunc_key,
						  auth_trunc_key_len);
		algo_auth_trunc->alg_trunc_len = 96;
		break;
	case CRYPTO_AUTH_HMAC_XCBC:
		algo_auth = auth_algo_alloc("xcbc(aes)",
					    auth_key, auth_key_len);
		algo_auth_trunc = NULL;
		break;
	case CRYPTO_AUTH_NULL:
		algo_auth = auth_algo_alloc("aNULL", auth_key, 0);
		algo_auth_trunc = NULL;
		break;
	default:
		_dp_test_fail(file, line, "Unhandled SA auth algorithm: %d",
			      sa->auth_algo);
		return;
	}

	/*
	 * Set up cipher algorithm. If a key is not specified,
	 * ues the default AES CBC 256 bit key.
	 */
	if (sa->cipher_key) {
		cipher_key_len = sa->cipher_key_len;
		cipher_key = sa->cipher_key;
	} else {
		cipher_key_len = sizeof(default_cipher_key) * 8;
		cipher_key = default_cipher_key;
	}

	switch (sa->cipher_algo) {
	case CRYPTO_CIPHER_AES_CBC:
		cipher_algo = cipher_algo_alloc("cbc(aes)",
						cipher_key, cipher_key_len);
		break;
	case CRYPTO_CIPHER_AES128GCM:
		aead_algo = algo_aead_alloc("rfc4106(gcm(aes))",
					    cipher_key, AES128GM_KEY_LEN);
		break;
	case CRYPTO_CIPHER_NULL:
		cipher_algo = cipher_algo_alloc("eNULL", cipher_key, 0);
		break;
	default:
		_dp_test_fail(file, line, "Unhandled SA cipher algorithm: %d",
			      sa->cipher_algo);
		return;
	}

	_dp_test_netlink_xfrm_newsa(sa->spi, sa->d_addr, sa->s_addr,
				    sa->family, sa->mode,
				    sa->reqid, cipher_algo, algo_auth,
				    algo_auth_trunc, aead_algo, sa->flags,
				    sa->extra_flags,
				    sa->encap_tmpl, sa->mark, sa->vrfid,
				    file, func, line);

	if (verify)
		_wait_for_sa(sa, true, file, line);

	free(aead_algo);
	free(cipher_algo);
	free(algo_auth_trunc);
	free(algo_auth);
}

void _dp_test_crypto_delete_sa_verify(const char *file, int line,
				      const struct dp_test_crypto_sa *sa,
				      bool verify)
{
	dp_test_netlink_xfrm_delsa(sa->spi, sa->d_addr, sa->s_addr,
				   sa->family, sa->mode, sa->reqid,
				   sa->vrfid);
	if (verify)
		_wait_for_sa(sa, false, file, line);
}

void _dp_test_crypto_expire_sa(const char *file, int line,
			       const struct dp_test_crypto_sa *sa, bool hard)
{
	dp_test_netlink_xfrm_expire(sa->spi, sa->d_addr, sa->s_addr,
				    sa->family, sa->mode, sa->reqid, hard,
				    sa->vrfid);
	/*
	 * After we send a hard expire, the SA should be
	 * removed from the dataplane, but it should still
	 * be there if we sent a soft expire message.
	 */
	_wait_for_sa(sa, !hard, file, line);
}

void _dp_test_crypto_check_sad_packets(
	vrfid_t vrfid, uint64_t packets, uint64_t bytes,
	const char *file, int line)
{
	char cmd_str[100];
	char exp_str[100];

	vrfid = dp_test_translate_vrf_id(vrfid);

	snprintf(cmd_str, sizeof(cmd_str), "ipsec sad vrf_id %d", vrfid);
	snprintf(exp_str, sizeof(exp_str), "\"bytes\": %"PRIu64, bytes);
	_dp_test_check_state_show(file, line, cmd_str, exp_str, false,
				  DP_TEST_CHECK_STR_SUBSET);
	snprintf(exp_str, sizeof(exp_str), "\"packets\": %"PRIu64, packets);
	_dp_test_check_state_show(file, line, cmd_str, exp_str, false,
				  DP_TEST_CHECK_STR_SUBSET);
}

void _dp_test_crypto_check_sa_count(
	vrfid_t vrfid, unsigned int num_sas,
	const char *file, int line)
{
	char cmd_str[100];
	char exp_str[100];

	vrfid = dp_test_translate_vrf_id(vrfid);

	snprintf(cmd_str, sizeof(cmd_str), "ipsec sad vrf_id %d", vrfid);
	snprintf(exp_str, sizeof(exp_str), "\"total-sas\": %u", num_sas);
	_dp_test_check_state_show(file, line, cmd_str, exp_str, false,
				  DP_TEST_CHECK_STR_SUBSET);
	dp_test_crypto_check_xfrm_acks();
}

struct dp_test_expected *
generate_exp_unreachable(struct rte_mbuf *input_pkt, int payload_len,
			 const char *source_ip, const char *dest_ip,
			 const char *oif, const char *dmac)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *icmp_pak;
	struct icmphdr *icph;
	struct iphdr *ip;
	int icmplen;

	/* Create expected icmp packet  */
	icmplen = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len;
	icmp_pak = dp_test_create_icmp_ipv4_pak(source_ip, dest_ip,
						ICMP_DEST_UNREACH,
						ICMP_NET_UNREACH,
						DPT_ICMP_UNREACH_DATA(0),
						1, &icmplen,
						iphdr(input_pkt),
						&ip, &icph);
	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       dmac,
				       dp_test_intf_name2mac_str(oif),
				       RTE_ETHER_TYPE_IPV4);

	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TOS,
				 IPTOS_PREC_INTERNETCONTROL);
	exp = dp_test_exp_create(icmp_pak);
	rte_pktmbuf_free(icmp_pak);
	dp_test_exp_set_oif_name(exp, oif);

	return exp;
}

struct dp_test_expected *
generate_exp_unreachable6(struct rte_mbuf *input_pkt, int payload_len,
			  const char *source_ip, const char *dest_ip,
			  const char *oif, const char *dmac)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *icmp_pak;
	int icmplen;
	struct ip6_hdr *inner_ip = ip6hdr(input_pkt);
	struct icmp6_hdr *icmp6;

	icmplen = sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr) +
		payload_len;

	icmp_pak = dp_test_create_icmp_ipv6_pak(source_ip, dest_ip,
						ICMP6_DST_UNREACH,
						ICMP6_DST_UNREACH_ADMIN,
						0, 1, &icmplen, inner_ip,
						NULL, &icmp6);

	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       dmac,
				       dp_test_intf_name2mac_str(oif),
				       RTE_ETHER_TYPE_IPV6);

	exp = dp_test_exp_create(icmp_pak);

	inner_ip = (struct ip6_hdr *)(icmp6 + 1);
	inner_ip->ip6_hlim--;
	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = dp_test_ipv6_icmp_cksum(icmp_pak,
						     ip6hdr(icmp_pak),
						     icmp6);
	rte_pktmbuf_free(icmp_pak);
	dp_test_exp_set_oif_name(exp, oif);

	return exp;
}

void _dp_test_xfrm_set_nack(uint32_t err_count)
{
	xfrm_ack_err = err_count;
}
