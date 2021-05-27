/*-
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
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

#include "protobuf/VFPSetConfig.pb-c.h"
#include "protobuf/CryptoPolicyConfig.pb-c.h"

#include "dp_test_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test/dp_test_macros.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test/dp_test_crypto_utils.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test/dp_test_cmd_check.h"
#include "dp_test_json_utils.h"
#include "dp_test_xfrm_server.h"
#include "dp_test_controller.h"
#include "dp_test_npf_lib.h"

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
		dp_test_abort_internal();

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
		dp_test_abort_internal();

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
		dp_test_abort_internal();

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
		dp_test_abort_internal();

	if (dp_test_prefix_str_to_xfrm_addr(s_prefix, &sel->saddr,
					    &sel->prefixlen_s, family))
		dp_test_abort_internal();

	sel->family = family;
	sel->proto = proto;
}

static uint32_t poll_cnt;

struct dp_test_crypto_reponses_cb {
	enum dp_test_crypto_check_resp_type type;
	bool match;
	bool valid;
	/* Expected values */
	uint64_t pkts;
	uint64_t bytes;
	/* Record the tested values */
	uint32_t tx_ack;
	uint32_t rx_ack;
	uint64_t actual_pkts;
	uint64_t actual_bytes;
};

static int _dp_test_crypto_poll_response(zloop_t *loop, int poller, void *arg)
{
	struct dp_test_crypto_reponses_cb *aux;

	aux = (struct dp_test_crypto_reponses_cb *) arg;
	poll_cnt--;

	switch (aux->type) {
	case DP_TEST_CHECK_CRYPTO_SEQ:
		aux->tx_ack = xfrm_seq;
		aux->rx_ack = xfrm_seq_received;
		if (aux->tx_ack == aux->rx_ack)
			aux->valid = true;
		break;
	case DP_TEST_CHECK_CRYPTO_SA_STATS:
		aux->actual_pkts = xfrm_packets;
		aux->actual_bytes = xfrm_bytes;
		if (aux->match) {
			if (aux->pkts == aux->actual_pkts &&
			    aux->bytes == aux->actual_bytes)
				aux->valid = true;
		} else {
			if (aux->pkts != aux->actual_pkts ||
			    aux->bytes != aux->actual_bytes)
				aux->valid = true;
		}
		break;
	default:
		dp_test_assert_internal(false);
	}
	/* return -1 to stop if we got what we want or run out of retries */
	return (aux->valid || poll_cnt == 0) ? -1 : 0;
}

/*
 * Check the xfrm responses received, either
 * - The number of rx acks sent versus the number of tx acks received.
 * - The stats on a particular SA versus those as expected.
 */
void
_dp_test_crypto_check_xfrm_resp(const char *file, int line,
				enum dp_test_crypto_check_resp_type type,
				uint64_t exp_bytes,
				uint64_t exp_packets,
				bool match)
{
	struct dp_test_crypto_reponses_cb aux;
	int timer;
	zloop_t *loop = zloop_new();

	aux.type = type;
	aux.match = match;
	aux.valid = false;
	aux.bytes = exp_bytes;
	aux.pkts = exp_packets;

	poll_cnt = DP_TEST_POLL_COUNT;
	timer = zloop_timer(loop, DP_TEST_POLL_INTERVAL, 0,
			    _dp_test_crypto_poll_response,
			    &aux);
	dp_test_assert_internal(timer >= 0);

	zloop_start(loop);
	zloop_destroy(&loop);

	if (!aux.valid)
		switch (type) {
		case DP_TEST_CHECK_CRYPTO_SEQ:
			_dp_test_fail(file, line, "Missing acks Tx %d Rx %d:\n",
				      aux.tx_ack, aux.rx_ack);
			break;
		case DP_TEST_CHECK_CRYPTO_SA_STATS:
			_dp_test_fail(file, line, "SA stats expected "
				      "pkts %lu bytes %lu, "
				      "got pkts %lu btyes %lu\n",
				      aux.pkts, aux.bytes, aux.actual_pkts,
				      aux.actual_bytes);
			break;
		default:
			dp_test_assert_internal(false);
		}
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
}

/*
 * _dp_test_create_ipsec_policy()
 *
 * Create or Update an IPsec policy in the dataplane
 */
void _dp_test_crypto_create_policy(const char *file, int line,
				   const struct dp_test_crypto_policy *policy,
				   bool verify, bool update, bool commit)
{
	struct xfrm_selector sel;
	xfrm_address_t dst;
	int action = update ? XFRM_MSG_UPDPOLICY : XFRM_MSG_NEWPOLICY;

	build_xfrm_selector(&sel, policy->d_prefix, policy->s_prefix,
			    policy->proto, policy->family);

	if (dp_test_prefix_str_to_xfrm_addr(policy->dst, &dst,
					    NULL, policy->dst_family))
		dp_test_abort_internal();

	_dp_test_netlink_xfrm_policy(action,
				     &sel, &dst,
				     policy->dst_family,
				     policy->dir,
				     policy->priority,
				     policy->reqid,
				     policy->mark,
				     policy->action,
				     policy->vrfid,
				     policy->passthrough,
				     policy->rule_no,
				     commit,
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
				   bool verify, bool commit)
{
	struct xfrm_selector sel;
	xfrm_address_t dst;

	build_xfrm_selector(&sel, policy->d_prefix, policy->s_prefix,
			    policy->proto, policy->family);

	if (dp_test_prefix_str_to_xfrm_addr(policy->dst, &dst,
					    NULL, policy->dst_family))
		dp_test_abort_internal();

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
				     policy->rule_no,
				     commit,
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

void _dp_test_crypto_get_sa(const char *file, int line,
				   const struct dp_test_crypto_sa *sa)
{
	dp_test_netlink_xfrm_getsa(sa->spi, sa->d_addr, sa->s_addr,
				   sa->family, sa->mode, sa->reqid,
				   sa->vrfid);
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

void  _dp_test_crypto_flush(void)
{
	nl_propagate_xfrm(xfrm_server_push_sock, NULL, 0, "FLUSH");
}

void  _dp_test_crypto_commit(void)
{
	nl_propagate_xfrm(xfrm_server_push_sock, NULL, 0, "COMMIT");
}

void _dp_test_xfrm_poison_sa_stats(void)
{
	xfrm_packets = 0xcafe;
	xfrm_bytes = 0xf00d;
}

static void
dp_test_create_and_send_s2s_msg(CryptoPolicyConfig__Action action,
				int af,
				int ifindex,
				int vrf,
				const char *daddr,
				uint32_t dprefix_len,
				const char *saddr,
				uint32_t sprefix_len,
				uint32_t dport,
				uint32_t sport,
				uint32_t proto,
				int sel_ifindex)
{
	int len;

	CryptoPolicyConfig con = CRYPTO_POLICY_CONFIG__INIT;
	con.has_action = true;
	con.action = action;
	con.has_ifindex = true;
	con.ifindex = ifindex;
	con.has_vrf = true;
	con.vrf = vrf;
	con.has_sel_dprefix_len = true;
	con.sel_dprefix_len = dprefix_len;
	con.has_sel_sprefix_len = true;
	con.sel_sprefix_len = sprefix_len;
	con.has_sel_dport = true;
	con.sel_dport = dport;
	con.has_sel_sport = true;
	con.sel_sport = sport;
	con.has_sel_ifindex = true;
	con.sel_ifindex = sel_ifindex;

	uint32_t v6_saddr[4], v6_daddr[4];
	IPAddress ip_daddr = IPADDRESS__INIT;
	IPAddress ip_saddr = IPADDRESS__INIT;

	dp_test_lib_pb_set_ip_addr(&ip_saddr, saddr, &v6_saddr);
	con.sel_saddr = &ip_saddr;

	dp_test_lib_pb_set_ip_addr(&ip_daddr, daddr, &v6_daddr);
	con.sel_daddr = &ip_daddr;

	len = crypto_policy_config__get_packed_size(&con);
	void *buf2 = malloc(len);
	dp_test_assert_internal(buf2);

	crypto_policy_config__pack(&con, buf2);

	dp_test_lib_pb_wrap_and_send_pb("vyatta:crypto-policy", buf2, len);
}

static void
dp_test_create_and_send_vfp_set_msg(const char *intf,
				    uint32_t ifindex,
				    VFPSetConfig__Action action)
{
	int len;

	VFPSetConfig vfp = VFPSET_CONFIG__INIT;
	vfp.if_name = (char *)intf;
	vfp.has_if_index = true;
	vfp.if_index = ifindex;
	vfp.has_action = true;
	vfp.action = action;
	vfp.has_type = true;
	vfp.type = VFPSET_CONFIG__VFPTYPE__VFP_S2S_CRYPTO;

	len = vfpset_config__get_packed_size(&vfp);
	void *buf2 = malloc(len);
	dp_test_assert_internal(buf2);

	vfpset_config__pack(&vfp, buf2);

	dp_test_lib_pb_wrap_and_send_pb("vyatta:vfp-set", buf2, len);
}

void _dp_test_s2s_add_vfp_and_bind(struct dp_test_s2s_config *conf,
				   const char *file, const char *func,
				   int line)
{
	int ifi;
	char vfp_match[256];

	/*
	 * If vfp_out_of_order is set then the vfp get and s2s binds
	 * are sent before the interface netlink to check we can handle
	 * this race condition.
	 */

	if (conf->vfp_out_of_order) {
		dp_test_intf_virt_add(conf->iface_vfp);
	} else {
		dp_test_intf_vfp_create(conf->iface_vfp, conf->vrfid);
		_dp_test_netlink_add_ip_address(conf->iface_vfp,
						conf->iface_vfp_ip,
						VRF_DEFAULT_ID, true, file,
						func, line);
	}

	ifi = dp_test_intf_name2index(conf->iface_vfp);

	dp_test_create_and_send_vfp_set_msg(conf->iface_vfp, ifi,
		VFPSET_CONFIG__ACTION__VFP_ACTION_GET);

	dp_test_create_and_send_s2s_msg(
					CRYPTO_POLICY_CONFIG__ACTION__ATTACH,
					conf->af,
					ifi,
					conf->vrfid,
					conf->network_remote_ip,
					conf->network_remote_mask,
					conf->network_local_ip,
					conf->network_local_mask,
					0, 0, 0, 0);

	snprintf(vfp_match, sizeof(vfp_match),
		 "\"virtual-feature-point_name\": \"%s\"", conf->iface_vfp);

	_dp_test_check_state_show(file, line, "ipsec bind", vfp_match, false,
				  DP_TEST_CHECK_STR_SUBSET);

	if (conf->vfp_out_of_order) {
		_dp_test_netlink_create_vfp(conf->iface_vfp, conf->vrfid,
					    false, file, func, line);
		_dp_test_netlink_add_ip_address(conf->iface_vfp,
						conf->iface_vfp_ip,
						VRF_DEFAULT_ID, true, file,
						func, line);
	}
}

void _dp_test_s2s_del_vfp_and_unbind(struct dp_test_s2s_config *conf,
				     const char *file, const char *func,
				     int line)
{
	bool verify = true;
	int ifi = dp_test_intf_name2index(conf->iface_vfp);

	dp_test_create_and_send_s2s_msg(
					CRYPTO_POLICY_CONFIG__ACTION__DETACH,
					conf->af,
					ifi,
					conf->vrfid,
					conf->network_remote_ip,
					conf->network_remote_mask,
					conf->network_local_ip,
					conf->network_local_mask,
					0, 0, 0, 0);

	dp_test_create_and_send_vfp_set_msg(conf->iface_vfp,
			    ifi, VFPSET_CONFIG__ACTION__VFP_ACTION_PUT);

	_dp_test_netlink_del_ip_address(conf->iface_vfp, conf->iface_vfp_ip,
					VRF_DEFAULT_ID, verify, file, func,
					line);
	_dp_test_intf_vfp_delete(conf->iface_vfp, conf->vrfid, file,
				 func, line);
}

void _dp_test_s2s_setup_interfaces(struct dp_test_s2s_config *conf,
				   const char *file, const char *func,
				   int line)
{
	char route_name[DP_TEST_MAX_ROUTE_STRING_LEN];
	bool verify = true;
	bool incomplete = false;

	if (conf->vrfid != VRF_DEFAULT_ID) {
		if (conf->out_of_order == VRF_XFRM_IN_ORDER) {
			_dp_test_netlink_add_vrf(conf->vrfid, 1, file, line);
		} else {
			_dp_test_netlink_add_vrf_incmpl(conf->vrfid, 1,
							file, line);
			return;
		}
	}

	if (conf->with_vfp == VFP_TRUE)
		_dp_test_s2s_add_vfp_and_bind(conf, file, func, line);
	_dp_test_netlink_set_interface_vrf(conf->iface1, conf->vrfid, verify,
					   file, func, line);
	_dp_test_nl_add_ip_addr_and_connected(conf->iface1,
					      conf->iface1_ip_with_mask,
					      conf->vrfid, file, func, line);
	_dp_test_netlink_add_neigh(conf->iface1, conf->client_local_ip,
				   conf->client_local_mac,
				   verify, file, func, line);
	/* At the moment iface2 is the transport vrf, and always in default */
	_dp_test_netlink_set_interface_vrf(conf->iface2, VRF_DEFAULT_ID,
					   verify, file, func, line);
	_dp_test_nl_add_ip_addr_and_connected(conf->iface2,
					      conf->iface2_ip_with_mask,
					      VRF_DEFAULT_ID,
					      file, func, line);
	_dp_test_netlink_add_neigh(conf->iface2, conf->peer_ip, conf->peer_mac,
				   verify, file, func, line);

	snprintf(route_name, sizeof(route_name),
		 "vrf:%d %s nh %s int:%s", VRF_DEFAULT_ID,
		 conf->network_remote_ip_with_mask, conf->peer_ip,
		 conf->iface2);

	_dp_test_netlink_add_route(route_name, verify, incomplete,
				   file, func, line);
}

void _dp_test_s2s_setup_interfaces_finish(struct dp_test_s2s_config *conf,
					  const char *file, const char *func,
					  int line)
{
	char route_name[DP_TEST_MAX_ROUTE_STRING_LEN];

	if (conf->vrfid != VRF_DEFAULT_ID)
		_dp_test_netlink_add_vrf(conf->vrfid, 1, file, line);

	if (conf->with_vfp == VFP_TRUE)
		_dp_test_s2s_add_vfp_and_bind(conf, file, func, line);
	dp_test_netlink_set_interface_vrf(conf->iface1, conf->vrfid);
	dp_test_nl_add_ip_addr_and_connected_vrf(conf->iface1,
						 conf->iface1_ip_with_mask,
						 conf->vrfid);
	dp_test_netlink_add_neigh(conf->iface1, conf->client_local_ip,
				  conf->client_local_mac);
	/* At the moment iface2 is the transport vrf, and always in default */
	dp_test_netlink_set_interface_vrf(conf->iface2, VRF_DEFAULT_ID);
	dp_test_nl_add_ip_addr_and_connected_vrf(conf->iface2,
						 conf->iface2_ip_with_mask,
						 VRF_DEFAULT_ID);
	dp_test_netlink_add_neigh(conf->iface2, conf->peer_ip, conf->peer_mac);

	snprintf(route_name, sizeof(route_name),
		 "vrf:%d %s nh %s int:%s", VRF_DEFAULT_ID,
		 conf->network_remote_ip_with_mask, conf->peer_ip,
		 conf->iface2);

	dp_test_netlink_add_route(route_name);
}

void dp_test_s2s_common_setup(struct dp_test_s2s_config *conf)
{
	/***************************************************
	 * Configure underlying topology
	 */
	bool verify = true;
	int i;

	dp_test_s2s_setup_interfaces(conf);

	if (conf->out_of_order == VRF_XFRM_OUT_OF_ORDER) {
		verify = false;
		/*
		 * We expect the update to fail due to incomplete
		 * interfaces so check for that
		 */
		dp_test_crypto_xfrm_set_nack(conf->nipols + conf->nopols);
	}

	for (i = 0; i < conf->nipols; i++) {
		conf->ipolicy[i].vrfid = conf->vrfid;
		dp_test_crypto_create_policy_verify(&(conf->ipolicy[i]),
						    verify);
	}

	for (i = 0; i < conf->nopols; i++) {
		conf->opolicy[i].vrfid = conf->vrfid;
		dp_test_crypto_create_policy_verify(&(conf->opolicy[i]),
						    verify);
	}

	dp_test_crypto_check_sa_count(VRF_DEFAULT_ID, 0);
	if (conf->with_vfp == VFP_TRUE)
		dp_test_check_state_show("ipsec spd",
					 "virtual-feature-point", false);

	conf->input_sa.auth_algo = conf->auth_algo;
	conf->input_sa.cipher_algo = conf->cipher_algo;
	conf->input_sa.mode = conf->mode;
	conf->input_sa.vrfid = conf->vrfid;

	conf->output_sa.auth_algo = conf->auth_algo;
	conf->output_sa.cipher_algo = conf->cipher_algo;
	conf->output_sa.mode = conf->mode;
	conf->output_sa.vrfid = conf->vrfid;

	if (conf->out_of_order == VRF_XFRM_OUT_OF_ORDER)
		/*
		 * We expect the sa creates to fail due to incomplete
		 * interfaces so check for that
		 */
		dp_test_crypto_xfrm_set_nack(2);

	dp_test_crypto_create_sa_verify(&(conf->input_sa), verify);
	dp_test_crypto_create_sa_verify(&(conf->output_sa), verify);

	if (conf->out_of_order == VRF_XFRM_OUT_OF_ORDER) {
		/*
		 * We need to put a scheduling barrier between the two
		 * SA creations above and the completion of interface
		 * setup up below.  There is a potential reordering
		 * race where the the interface could become complete
		 * in the dataplane before the attempted creation of
		 * the SAs above in the dataplane, and so rather than
		 * return an error as expected it returns OK.
		 */
		dp_test_crypto_check_xfrm_acks();

		dp_test_s2s_setup_interfaces_finish(conf);

		for (i = 0; i < conf->nipols; i++)
			dp_test_crypto_create_policy_verify(
				&(conf->ipolicy[i]), true);
		for (i = 0; i < conf->nopols; i++)
			dp_test_crypto_create_policy_verify(
				&(conf->opolicy[i]), true);

		dp_test_crypto_create_sa_verify(&(conf->input_sa), true);
		dp_test_crypto_create_sa_verify(&(conf->output_sa), true);
	}

	if (conf->with_vfp == VFP_TRUE)
		dp_test_check_state_show("ipsec sad",
					 "virtual-feature-point", false);
}

void _dp_test_s2s_teardown_interfaces(struct dp_test_s2s_config *conf,
				      bool leave_vrf, const char *file,
				      const char *func, int line)
{
	bool verify = true;
	char route_name[DP_TEST_MAX_ROUTE_STRING_LEN];

	_dp_test_netlink_del_neigh(conf->iface2, conf->peer_ip,
				   conf->peer_mac, verify, file, func, line);
	snprintf(route_name, sizeof(route_name),
		 "vrf:%d %s nh %s int:%s", VRF_DEFAULT_ID,
		 conf->network_remote_ip_with_mask, conf->peer_ip,
		 conf->iface2);
	_dp_test_netlink_del_route(route_name, verify, file, func, line);
	_dp_test_nl_del_ip_addr_and_connected(conf->iface2,
					      conf->iface2_ip_with_mask,
					      VRF_DEFAULT_ID,
					      file, func, line);
	_dp_test_netlink_del_neigh(conf->iface1, conf->client_local_ip,
				   conf->client_local_mac,
				   verify, file, func, line);
	_dp_test_nl_del_ip_addr_and_connected(conf->iface1,
					      conf->iface1_ip_with_mask,
					      conf->vrfid, file, func, line);
	_dp_test_netlink_set_interface_vrf(conf->iface1, VRF_DEFAULT_ID,
					   verify, file, func, line);
	_dp_test_netlink_set_interface_vrf(conf->iface1, VRF_DEFAULT_ID,
					   verify, file, func, line);
	if (conf->with_vfp == VFP_TRUE)
		_dp_test_s2s_del_vfp_and_unbind(conf, file, func, line);
	if (!leave_vrf && (conf->vrfid != VRF_DEFAULT_ID))
		_dp_test_netlink_del_vrf(conf->vrfid, 0, file, line);
}

void dp_test_s2s_common_teardown(struct dp_test_s2s_config *conf)
{
	int i;

	if (conf->out_of_order == VRF_XFRM_OUT_OF_ORDER) {
		/*
		 * Tear down the vrf first, this should cause
		 * a flush of all the ipsec state.
		 */
		dp_test_s2s_teardown_interfaces(conf);
		return;
	}

	dp_test_crypto_delete_sa(&(conf->input_sa));
	dp_test_crypto_delete_sa(&(conf->output_sa));

	for (i = 0; i < conf->nipols; i++)
		dp_test_crypto_delete_policy(&(conf->ipolicy[i]));

	for (i = 0; i < conf->nopols; i++)
		dp_test_crypto_delete_policy(&(conf->opolicy[i]));

	/***************************************************
	 * Tear down topology
	 */
	dp_test_s2s_teardown_interfaces(conf);
	dp_test_npf_cleanup();
}
