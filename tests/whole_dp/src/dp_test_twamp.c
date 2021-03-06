/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * TWAMP offload test cases
 */
#include <errno.h>
#include <time.h>
#include <string.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "ip6_funcs.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_console.h"
#include "dp_test/dp_test_cmd_check.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_pkt.h"

#include "protobuf/TwampResponder.pb-c.h"
#include "protobuf/DataplaneEnvelope.pb-c.h"

#define PORT1 9123
#define PORT2 9345
#define PORT3 9321
#define PORT4 9543

#define TWAMP_TEST_RX_PKT_SIZE_UNAUTH 14
#define TWAMP_TEST_TX_PKT_SIZE_UNAUTH 41
#define TWAMP_TEST_RX_PKT_SIZE_AUTH   48
#define TWAMP_TEST_TX_PKT_SIZE_AUTH   104

#define DEFAULT_TWAMP_PADDING_SIZE 23
#define DEFAULT_TWAMP_SIZE (TWAMP_TEST_TX_PKT_SIZE_UNAUTH + DEFAULT_TWAMP_PADDING_SIZE)
#define DEFAULT_PKT_SIZE (DEFAULT_TWAMP_SIZE + sizeof(struct udphdr))
#define MIN_RX_PKT_SIZE (TWAMP_TEST_RX_PKT_SIZE_UNAUTH + sizeof(struct udphdr))
#define MIN_TX_PKT_SIZE (TWAMP_TEST_TX_PKT_SIZE_UNAUTH + sizeof(struct udphdr))

struct tw_address {
	const char *addrstr;
	uint32_t ip6data[4];
	IPAddress ipaddr;
	char addrbuf[INET6_ADDRSTRLEN];
};

struct dp_test_twamp_response {
	int status;
	int has_counters;
	uint32_t tx_pkts;
	uint32_t rx_pkts;
};

struct tw_pkt_desc {
	struct tw_address laddr;
	struct tw_address raddr;
	uint16_t lport;
	uint16_t rport;
	uint32_t sseqno;
	uint32_t rseqno;
	int sndpktlen;
	int rcvpktlen;
	char *oif;
	char *macaddr;
};

static bool
dp_test_twamp_check_resp(void *data, int len, void *arg)
{
	DataplaneEnvelope *dpresp;
	TWAMPCmdResponse *twresp = NULL;
	TWAMPSessionCounterResponse *counters;
	struct dp_test_twamp_response *resp = arg;

	memset(resp, 0xff, sizeof(*resp));
	resp->has_counters = 0;

	dpresp = dataplane_envelope__unpack(NULL, len, data);
	if (dpresp == NULL) {
		printf("TWAMP: cannot unpack dataplane envelope\n");
		return false;
	}

	twresp = twampcmd_response__unpack(NULL,
					   dpresp->msg.len,
					   dpresp->msg.data);
	if (twresp == NULL) {
		printf("TWAMP: unable to read protobuf message: %lud, %p\n",
		       dpresp->msg.len, dpresp->msg.data);
		dataplane_envelope__free_unpacked(dpresp, NULL);
		return false;
	}

	resp->status = twresp->status;
	counters = twresp->counters;
	if (counters != NULL) {
		resp->has_counters = 1;
		if (counters->has_rx_pkts)
			resp->rx_pkts = counters->rx_pkts;
		if (counters->has_tx_pkts)
			resp->tx_pkts = counters->tx_pkts;
	}

	twampcmd_response__free_unpacked(twresp, NULL);
	dataplane_envelope__free_unpacked(dpresp, NULL);
	return true;
}

static void
dp_test_twamp_build_key(TWAMPSessionKey *key,
			struct tw_address *laddr, struct tw_address *raddr,
			uint16_t lport, uint16_t rport)
{
	twampsession_key__init(key);
	ipaddress__init(&laddr->ipaddr);
	ipaddress__init(&raddr->ipaddr);
	dp_test_lib_pb_set_ip_addr(&laddr->ipaddr, laddr->addrstr,
				   &laddr->ip6data);
	dp_test_lib_pb_set_ip_addr(&raddr->ipaddr, raddr->addrstr,
				   &raddr->ip6data);
	key->laddr = &laddr->ipaddr;
	key->raddr = &raddr->ipaddr;
	key->has_lport = true;
	key->lport = lport;
	key->has_rport = true;
	key->rport = rport;
}

static void *
dp_test_twamp_build_cmd(TWAMPCmd__MtypeCase type, void *msg, size_t *retlen)
{
	DataplaneEnvelope envelope = DATAPLANE_ENVELOPE__INIT;
	TWAMPCmd cmd = TWAMPCMD__INIT;
	size_t len, packed_len;
	void *buf1, *buf2;

	cmd.mtype_case = type;
	switch (type) {
	case TWAMPCMD__MTYPE_TW_INIT:
		cmd.tw_init = msg;
		break;
	case TWAMPCMD__MTYPE_TWS_DELETE:
		cmd.tws_delete = msg;
		break;
	case TWAMPCMD__MTYPE_TWS_CREATE:
		cmd.tws_create = msg;
		break;
	case TWAMPCMD__MTYPE_TWS_COUNTERS:
		cmd.tws_counters = msg;
		break;
	default:
		dp_test_assert_internal(false);
		break;
	}

	len = twampcmd__get_packed_size(&cmd);
	buf1 = malloc(len);
	dp_test_assert_internal(buf1 != NULL);
	packed_len = twampcmd__pack(&cmd, buf1);
	dp_test_assert_internal(len == packed_len);

	envelope.type = strdup("vyatta:twamp");
	envelope.msg.data = buf1;
	envelope.msg.len = packed_len;
	len = dataplane_envelope__get_packed_size(&envelope);
	buf2 = malloc(len);
	dp_test_assert_internal(buf2 != NULL);
	packed_len = dataplane_envelope__pack(&envelope, buf2);
	dp_test_assert_internal(len == packed_len);

	free(envelope.type);
	free(buf1);

	*retlen = packed_len;
	return buf2;
}

static void
dp_test_twamp_build_counters(TWAMPSessionCounters *counters,
			     TWAMPSessionKey *key,
			     struct dp_test_twamp_response *resp)
{
	size_t len;
	void *msg;

	twampsession_counters__init(counters);
	counters->key = key;
	msg = dp_test_twamp_build_cmd(TWAMPCMD__MTYPE_TWS_COUNTERS, counters,
				      &len);
	dp_test_check_pb_state(msg, len, dp_test_twamp_check_resp, resp);
	free(msg);
}

static void
dp_test_twamp_build_delete(TWAMPSessionDelete *delete,
			   TWAMPSessionKey *key,
			   struct dp_test_twamp_response *resp)
{
	size_t len;
	void *msg;

	twampsession_delete__init(delete);
	delete->key = key;
	msg = dp_test_twamp_build_cmd(TWAMPCMD__MTYPE_TWS_DELETE, delete,
				      &len);
	dp_test_check_pb_state(msg, len, dp_test_twamp_check_resp, resp);
	free(msg);
}

static void
dp_test_twamp_build_create(TWAMPSessionCreate *create,
			   TWAMPSessionKey *key,
			   TWAMPSessionCreate__Mode mode,
			   uint8_t dscp,
			   uint16_t rx_msg_size,
			   uint16_t tx_msg_size,
			   struct dp_test_twamp_response *resp)
{
	size_t len;
	void *msg;

	twampsession_create__init(create);
	create->key = key;
	create->has_mode = true;
	create->mode = mode;
	create->has_dscp = true;
	create->dscp = dscp;
	create->has_rx_payload_len = true;
	create->rx_payload_len = rx_msg_size;
	create->has_tx_payload_len = true;
	create->tx_payload_len = tx_msg_size;
	msg = dp_test_twamp_build_cmd(TWAMPCMD__MTYPE_TWS_CREATE, create,
				      &len);
	dp_test_check_pb_state(msg, len, dp_test_twamp_check_resp, resp);
	free(msg);
}

#define TWAMP_CREATE_DEFAULT(_c, _k, _r)				\
	dp_test_twamp_build_create(_c, _k,				\
				   TWAMPSESSION_CREATE__MODE__MODE_OPEN, \
				   0,					\
				   DEFAULT_TWAMP_SIZE, DEFAULT_TWAMP_SIZE, \
				   _r)

static void
dp_test_twamp_build_init(TWAMPInitialise *init,
			 const char *vrf,
			 struct dp_test_twamp_response *resp)
{
	size_t len;
	void *msg;

	twampinitialise__init(init);
	init->vrf_name = (char *)vrf;
	msg = dp_test_twamp_build_cmd(TWAMPCMD__MTYPE_TW_INIT, init,
				      &len);
	dp_test_check_pb_state(msg, len, dp_test_twamp_check_resp, resp);
	free(msg);
}

static void
dp_test_twamp_build_pkts(struct rte_mbuf *s, uint32_t sseqno, int s_ttlhop,
			 struct dp_test_expected *exp, uint32_t rseqno,
			 uint16_t lport, uint16_t rport,
			 bool is_v4)
{
	struct rte_mbuf *ep;
	struct udphdr *udp;
	uint8_t *tpkt;
	struct timespec sts;
	struct timespec rts;
	uint16_t errest_sender = 0;
	uint16_t errest_reply = 0;
	void *dont_care_udp_checksum;
	void *dont_care_ts_1;
	void *dont_care_ts_2;
	void *dont_care_errest;

	clock_gettime(CLOCK_REALTIME, &sts);
	udp = dp_pktmbuf_mtol4(s, struct udphdr *);
	tpkt = (uint8_t *)(udp + 1);

	*((uint32_t *)tpkt) = htonl(sseqno);
	tpkt += sizeof(uint32_t);
	*((uint32_t *)tpkt) = htonl(sts.tv_sec);
	tpkt += sizeof(uint32_t);
	*((uint32_t *)tpkt) = htonl(sts.tv_nsec);
	tpkt += sizeof(uint32_t);
	*((uint16_t *)tpkt) = htons(errest_sender);

	dp_test_pktmbuf_udp_init(s, rport, lport, is_v4);

	clock_gettime(CLOCK_REALTIME, &rts);

	ep = dp_test_exp_get_pak(exp);
	udp = dp_pktmbuf_mtol4(ep, struct udphdr *);
	tpkt = (uint8_t *)(udp + 1);

	*((uint32_t *)tpkt) = htonl(rseqno);
	tpkt += sizeof(uint32_t);

	dont_care_ts_1 = tpkt;
	*((uint32_t *)tpkt) = htonl(rts.tv_sec);
	tpkt += sizeof(uint32_t);
	*((uint32_t *)tpkt) = htonl(rts.tv_nsec);
	tpkt += sizeof(uint32_t);

	dont_care_errest = tpkt;
	*((uint16_t *)tpkt) = htons(errest_reply);
	tpkt += sizeof(uint16_t);
	*((uint16_t *)tpkt) = 0;
	tpkt += sizeof(uint16_t);

	rts.tv_sec++;
	rts.tv_nsec++;

	dont_care_ts_2 = tpkt;
	*((uint32_t *)tpkt) = htonl(rts.tv_sec);
	tpkt += sizeof(uint32_t);
	*((uint32_t *)tpkt) = htonl(rts.tv_nsec);
	tpkt += sizeof(uint32_t);

	*((uint32_t *)tpkt) = htonl(sseqno);
	tpkt += sizeof(uint32_t);

	*((uint32_t *)tpkt) = htonl(sts.tv_sec);
	tpkt += sizeof(uint32_t);
	*((uint32_t *)tpkt) = htonl(sts.tv_nsec);
	tpkt += sizeof(uint32_t);

	*((uint16_t *)tpkt) = htons(errest_sender);
	tpkt += sizeof(uint16_t);
	*((uint16_t *)tpkt) = 0;
	tpkt += sizeof(uint16_t);

	*((uint8_t *)tpkt) = s_ttlhop;

	dp_test_pktmbuf_udp_init(ep, lport, rport, is_v4);

	udp = dp_pktmbuf_mtol4(ep, struct udphdr *);
	dont_care_udp_checksum = &udp->check;

	/*
	 * Ignore the UDP checksum and the various timestamp fields in
	 * the expected reply packet.
	 */
	dp_test_exp_set_dont_care(exp, 0, dont_care_udp_checksum, 2);
	dp_test_exp_set_dont_care(exp, 0, dont_care_ts_1, 8);
	dp_test_exp_set_dont_care(exp, 0, dont_care_errest, 2);
	dp_test_exp_set_dont_care(exp, 0, dont_care_ts_2, 8);
}

static struct dp_test_expected *
dp_test_twamp_build_ipv6_pkts(struct tw_pkt_desc *pkt,
			      struct rte_mbuf **send_pak)
{
	struct rte_mbuf *ep;
	struct ip6_hdr *ip6;
	struct dp_test_expected *exp;
	struct rte_mbuf *s_pak;
	struct rte_mbuf *r_pak;
	int s_hlim = 255;
	int r_hlim = 255;

	s_pak = dp_test_create_raw_ipv6_pak(pkt->raddr.addrstr, pkt->laddr.addrstr,
					    IPPROTO_UDP,
					    1, &pkt->sndpktlen);
	r_pak = dp_test_create_raw_ipv6_pak(pkt->laddr.addrstr, pkt->raddr.addrstr,
					    IPPROTO_UDP,
					    1, &pkt->rcvpktlen);
	ip6 = ip6hdr(s_pak);
	ip6->ip6_hlim = s_hlim;
	ip6 = ip6hdr(r_pak);
	ip6->ip6_hlim = r_hlim;

	exp = dp_test_exp_create(r_pak);
	dp_test_assert_internal(exp != NULL);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);
	dp_test_exp_set_oif_name(exp, pkt->oif);
	rte_pktmbuf_free(r_pak);

	dp_test_twamp_build_pkts(s_pak, pkt->sseqno, s_hlim, exp, pkt->rseqno,
				 pkt->lport, pkt->rport, false);

	ep = dp_test_exp_get_pak(exp);
	(void)dp_test_pktmbuf_eth_init(s_pak,
				       dp_test_intf_name2mac_str(pkt->oif),
				       pkt->macaddr, RTE_ETHER_TYPE_IPV6);
	(void)dp_test_pktmbuf_eth_init(ep,
				       pkt->macaddr,
				       dp_test_intf_name2mac_str(pkt->oif),
				       RTE_ETHER_TYPE_IPV6);

	dp_test_assert_internal(ip6_valid_packet(s_pak, ip6hdr(s_pak)));
	dp_test_assert_internal(ip6_valid_packet(ep, ip6hdr(ep)));

	*send_pak = s_pak;
	return exp;
}

static struct dp_test_expected *
dp_test_twamp_build_ipv4_pkts(struct tw_pkt_desc *pkt,
			      struct rte_mbuf **send_pak,
			      bool addopts)
{
	struct rte_mbuf *ep;
	struct iphdr *ip;
	struct dp_test_expected *exp;
	struct rte_mbuf *s_pak;
	struct rte_mbuf *r_pak;
	int s_ttl = 255;
	int r_ttl = 255;
	int s_pktlen = pkt->sndpktlen;
	int optlen = 4;

	if (addopts)
		s_pktlen += optlen;

	s_pak = dp_test_create_raw_ipv4_pak(pkt->raddr.addrstr, pkt->laddr.addrstr,
					    IPPROTO_UDP,
					    1, &s_pktlen);
	rte_pktmbuf_adj(s_pak, s_pak->l2_len);
	s_pak->l2_len = 0;
	r_pak = dp_test_create_raw_ipv4_pak(pkt->laddr.addrstr, pkt->raddr.addrstr,
					    IPPROTO_UDP,
					    1, &pkt->rcvpktlen);

	ip = iphdr(r_pak);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TTL, r_ttl);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TOS,
				 IPTOS_PREC_INTERNETCONTROL);
	ip = iphdr(s_pak);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TTL, s_ttl);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TOS,
				 IPTOS_PREC_INTERNETCONTROL);

	if (addopts) {
		uint8_t *opts;
		void *newip;

		newip = rte_pktmbuf_prepend(s_pak, optlen);
		dp_test_assert_internal(newip != NULL);
		memmove(newip, ip, sizeof(*ip));
		ip = newip;

		opts = (uint8_t *)(ip + 1);
		opts[IPOPT_OPTVAL] = IPOPT_NOP;
		opts++;
		opts[IPOPT_OPTVAL] = IPOPT_NOP;
		opts++;
		opts[IPOPT_OPTVAL] = IPOPT_NOP;
		opts++;
		opts[IPOPT_OPTVAL] = IPOPT_EOL;
		ip->ihl = (sizeof(*ip) + optlen) / 4;
		ip->check = 0;
		ip->check = ip_checksum(ip, ip->ihl * 4);
		dp_pktmbuf_l3_len(s_pak) = sizeof(*ip) + optlen;
		dp_test_assert_internal(ip_valid_packet(s_pak, iphdr(s_pak)));
	}

	exp = dp_test_exp_create(r_pak);
	dp_test_assert_internal(exp != NULL);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);
	dp_test_exp_set_oif_name(exp, pkt->oif);
	rte_pktmbuf_free(r_pak);

	dp_test_twamp_build_pkts(s_pak, pkt->sseqno, s_ttl, exp, pkt->rseqno,
				 pkt->lport, pkt->rport, true);

	ep = dp_test_exp_get_pak(exp);
	(void)dp_test_pktmbuf_eth_prepend(s_pak,
				       dp_test_intf_name2mac_str(pkt->oif),
				       pkt->macaddr, RTE_ETHER_TYPE_IPV4);
	(void)dp_test_pktmbuf_eth_init(ep,
				       pkt->macaddr,
				       dp_test_intf_name2mac_str(pkt->oif),
				       RTE_ETHER_TYPE_IPV4);

	dp_test_assert_internal(ip_valid_packet(s_pak, iphdr(s_pak)));
	dp_test_assert_internal(ip_valid_packet(ep, iphdr(ep)));

	*send_pak = s_pak;
	return exp;
}

DP_DECL_TEST_SUITE(twamp_offload_suite);

DP_DECL_TEST_CASE(twamp_offload_suite, twamp_rxtx, NULL, NULL);

DP_START_TEST(twamp_rxtx, pktsize)
{
	TWAMPSessionCreate create;
	TWAMPSessionCounters counters;
	TWAMPSessionDelete delete;
	TWAMPSessionKey key4;
	TWAMPSessionKey key6;
	struct dp_test_twamp_response resp;
	struct dp_test_expected *exp4_pak;
	struct dp_test_expected *exp6_pak;
	struct rte_mbuf *s4_pak;
	struct rte_mbuf *s6_pak;
	struct tw_pkt_desc pkt6 = {
		.laddr.addrstr = "2001:1::1",
		.raddr.addrstr = "2001:1::3",
		.lport = PORT1,
		.rport = PORT3,
		.macaddr = "aa:bb:cc:dd:ee:ff",
		.oif = "dp1T0",
		.sndpktlen = MIN_RX_PKT_SIZE,
		.rcvpktlen = MIN_TX_PKT_SIZE,
	};
	struct tw_pkt_desc pkt4 = {
		.laddr.addrstr = "1.1.1.1",
		.raddr.addrstr = "1.1.1.3",
		.lport = PORT1,
		.rport = PORT3,
		.macaddr = "aa:bb:cc:dd:ee:ff",
		.oif = "dp1T0",
		.sndpktlen = MIN_RX_PKT_SIZE,
		.rcvpktlen = MIN_TX_PKT_SIZE,
	};

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_netlink_add_neigh("dp1T0", pkt4.raddr.addrstr, pkt4.macaddr);
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1::1/96");
	dp_test_netlink_add_neigh("dp1T0", pkt6.raddr.addrstr, pkt6.macaddr);

	exp6_pak = dp_test_twamp_build_ipv6_pkts(&pkt6, &s6_pak);
	pkt6.sseqno++;
	pkt6.rseqno++;

	exp4_pak = dp_test_twamp_build_ipv4_pkts(&pkt4, &s4_pak, false);
	pkt4.sseqno++;
	pkt4.rseqno++;

	/*
	 * Build IPv6 & IPv4 sessions with minimum send/receive
	 * message sizes (as opposed to adding padding such that the
	 * received message is large enough to accommodate the
	 * reflected message).
	 */
	dp_test_twamp_build_key(&key6, &pkt6.laddr, &pkt6.raddr,
				pkt6.lport, pkt6.rport);
	dp_test_twamp_build_create(&create, &key6,
				   TWAMPSESSION_CREATE__MODE__MODE_OPEN,
				   0,
				   TWAMP_TEST_RX_PKT_SIZE_UNAUTH,
				   TWAMP_TEST_TX_PKT_SIZE_UNAUTH,
				   &resp);
	dp_test_assert_internal(resp.status == 0);

	dp_test_twamp_build_key(&key4, &pkt4.laddr, &pkt4.raddr,
				pkt4.lport, pkt4.rport);
	dp_test_twamp_build_create(&create, &key4,
				   TWAMPSESSION_CREATE__MODE__MODE_OPEN,
				   0,
				   TWAMP_TEST_RX_PKT_SIZE_UNAUTH,
				   TWAMP_TEST_TX_PKT_SIZE_UNAUTH,
				   &resp);
	dp_test_assert_internal(resp.status == 0);

	dp_test_pak_receive(s4_pak, pkt4.oif, exp4_pak);
	dp_test_pak_receive(s6_pak, pkt6.oif, exp6_pak);

	dp_test_twamp_build_counters(&counters, &key4, &resp);
	dp_test_assert_internal(resp.status == 0);
	dp_test_assert_internal(resp.has_counters == 1);
	dp_test_assert_internal(resp.tx_pkts == 1);
	dp_test_assert_internal(resp.rx_pkts == 1);
	dp_test_twamp_build_counters(&counters, &key6, &resp);
	dp_test_assert_internal(resp.status == 0);
	dp_test_assert_internal(resp.has_counters == 1);
	dp_test_assert_internal(resp.tx_pkts == 1);
	dp_test_assert_internal(resp.rx_pkts == 1);

	json_object *jobj = dp_test_json_create(
		"{\"twamp-sessions\":"
		"["
		"{\"local-port\":%d,\"remote-port\":%d,"
		" \"local-address\":\"%s\",\"remote-address\":\"%s\","
		" \"rx-pkts\":%d, \"tx-pkts\":%d},"
		"{\"local-port\":%d,\"remote-port\":%d,"
		" \"local-address\":\"%s\",\"remote-address\":\"%s\","
		" \"rx-pkts\":%d,\"tx-pkts\":%d}"
		"]}",
		pkt4.lport, pkt4.rport, pkt4.laddr.addrstr, pkt4.raddr.addrstr, 1, 1,
		pkt6.lport, pkt6.rport, pkt6.laddr.addrstr, pkt6.raddr.addrstr, 1, 1);
	dp_test_check_json_state("vyatta:twamp dump", jobj,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(jobj);

	dp_test_twamp_build_delete(&delete, &key4, &resp);
	dp_test_assert_internal(resp.status == 0);
	dp_test_twamp_build_delete(&delete, &key6, &resp);
	dp_test_assert_internal(resp.status == 0);

	json_object *expected = dp_test_json_create("{\"twamp-sessions\":[]}");
	dp_test_check_json_state("vyatta:twamp dump", expected,
				 DP_TEST_JSON_CHECK_EXACT, false);
	json_object_put(expected);

	dp_test_netlink_del_neigh("dp1T0", pkt6.raddr.addrstr, pkt6.macaddr);
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1::1/96");
	dp_test_netlink_del_neigh("dp1T0", pkt4.raddr.addrstr, pkt4.macaddr);
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
} DP_END_TEST;

DP_START_TEST(twamp_rxtx, ip6)
{
	TWAMPSessionCreate create;
	TWAMPSessionCounters counters;
	TWAMPSessionDelete delete;
	TWAMPSessionKey key;
	struct dp_test_twamp_response resp;
	struct dp_test_expected *exp_pak;
	struct rte_mbuf *s_pak;
	struct tw_pkt_desc pkt = {
		.laddr.addrstr = "2001:1::1",
		.raddr.addrstr = "2001:1::3",
		.lport = PORT2,
		.rport = PORT3,
		.macaddr = "aa:bb:cc:dd:ee:ff",
		.oif = "dp1T0",
		.sndpktlen = DEFAULT_PKT_SIZE,
		.rcvpktlen = DEFAULT_PKT_SIZE,
	};

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1::1/96");
	dp_test_netlink_add_neigh("dp1T0", pkt.raddr.addrstr, pkt.macaddr);

	exp_pak = dp_test_twamp_build_ipv6_pkts(&pkt, &s_pak);
	pkt.sseqno++;
	pkt.rseqno++;

	dp_test_twamp_build_key(&key, &pkt.laddr, &pkt.raddr,
				pkt.lport, pkt.rport);
	TWAMP_CREATE_DEFAULT(&create, &key, &resp);
	dp_test_assert_internal(resp.status == 0);

	dp_test_pak_receive(s_pak, pkt.oif, exp_pak);

	dp_test_twamp_build_counters(&counters, &key, &resp);
	dp_test_assert_internal(resp.status == 0);
	dp_test_assert_internal(resp.has_counters == 1);
	dp_test_assert_internal(resp.tx_pkts == 1);
	dp_test_assert_internal(resp.rx_pkts == 1);

	json_object *jobj = dp_test_json_create(
		"{\"twamp-sessions\":"
		"["
		"{\"local-port\":%d,\"remote-port\":%d,"
		" \"local-address\":\"%s\",\"remote-address\":\"%s\","
		" \"rx-pkts\":%d}"
		"]}",
		pkt.lport, pkt.rport, pkt.laddr.addrstr, pkt.raddr.addrstr, 1);
	dp_test_check_json_state("vyatta:twamp dump", jobj,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(jobj);

	dp_test_twamp_build_delete(&delete, &key, &resp);
	dp_test_assert_internal(resp.status == 0);

	json_object *expected = dp_test_json_create("{\"twamp-sessions\":[]}");
	dp_test_check_json_state("vyatta:twamp dump", expected,
				 DP_TEST_JSON_CHECK_EXACT, false);
	json_object_put(expected);

	dp_test_netlink_del_neigh("dp1T0", pkt.raddr.addrstr, pkt.macaddr);
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1::1/96");
} DP_END_TEST;

DP_START_TEST(twamp_rxtx, ip4)
{
	TWAMPSessionCreate create;
	TWAMPSessionCounters counters;
	TWAMPSessionDelete delete;
	TWAMPSessionKey key;
	struct dp_test_twamp_response resp;
	struct dp_test_expected *exp_pak;
	struct rte_mbuf *s_pak;
	struct tw_pkt_desc pkt = {
		.laddr.addrstr = "1.1.1.1",
		.raddr.addrstr = "1.1.1.3",
		.lport = PORT2,
		.rport = PORT3,
		.macaddr = "aa:bb:cc:dd:ee:ff",
		.oif = "dp1T0",
		.sndpktlen = DEFAULT_PKT_SIZE,
		.rcvpktlen = DEFAULT_PKT_SIZE,
	};

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_netlink_add_neigh("dp1T0", pkt.raddr.addrstr, pkt.macaddr);

	exp_pak = dp_test_twamp_build_ipv4_pkts(&pkt, &s_pak, false);
	pkt.sseqno++;
	pkt.rseqno++;

	dp_test_twamp_build_key(&key, &pkt.laddr, &pkt.raddr,
				pkt.lport, pkt.rport);
	TWAMP_CREATE_DEFAULT(&create, &key, &resp);
	dp_test_assert_internal(resp.status == 0);

	dp_test_pak_receive(s_pak, pkt.oif, exp_pak);

	dp_test_twamp_build_counters(&counters, &key, &resp);
	dp_test_assert_internal(resp.status == 0);
	dp_test_assert_internal(resp.has_counters == 1);
	dp_test_assert_internal(resp.tx_pkts == 1);
	dp_test_assert_internal(resp.rx_pkts == 1);

	json_object *jobj = dp_test_json_create(
		"{\"twamp-sessions\":"
		"["
		"{\"local-port\":%d,\"remote-port\":%d,"
		" \"local-address\":\"%s\",\"remote-address\":\"%s\","
		" \"rx-pkts\":%d}"
		"]}",
		pkt.lport, pkt.rport, pkt.laddr.addrstr, pkt.raddr.addrstr, 1);
	dp_test_check_json_state("vyatta:twamp dump", jobj,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(jobj);

	exp_pak = dp_test_twamp_build_ipv4_pkts(&pkt, &s_pak, true);
	pkt.sseqno++;
	pkt.rseqno++;
	dp_test_pak_receive(s_pak, pkt.oif, exp_pak);

	dp_test_twamp_build_counters(&counters, &key, &resp);
	dp_test_assert_internal(resp.status == 0);
	dp_test_assert_internal(resp.has_counters == 1);
	dp_test_assert_internal(resp.tx_pkts == 2);
	dp_test_assert_internal(resp.rx_pkts == 2);

	dp_test_twamp_build_delete(&delete, &key, &resp);
	dp_test_assert_internal(resp.status == 0);

	json_object *expected = dp_test_json_create("{\"twamp-sessions\":[]}");
	dp_test_check_json_state("vyatta:twamp dump", expected,
				 DP_TEST_JSON_CHECK_EXACT, false);
	json_object_put(expected);

	dp_test_netlink_del_neigh("dp1T0", pkt.raddr.addrstr, pkt.macaddr);
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
} DP_END_TEST;

DP_DECL_TEST_CASE(twamp_offload_suite, twamp_session, NULL, NULL);

DP_START_TEST(twamp_session, errors)
{
	TWAMPSessionCreate create;
	TWAMPSessionCounters counters;
	TWAMPSessionDelete delete;
	TWAMPSessionKey key;
	struct tw_address laddr = {
		.addrstr = "1.1.1.1"
	};
	struct tw_address raddr = {
		.addrstr = "2.2.2.2"
	};
	uint16_t lport = PORT3;
	uint16_t rport = PORT4;
	struct dp_test_twamp_response resp;

	dp_test_twamp_build_key(&key, &laddr, &raddr, lport, rport);

	TWAMP_CREATE_DEFAULT(&create, &key, &resp);
	dp_test_assert_internal(resp.status == 0);
	dp_test_assert_internal(resp.has_counters == 0);

	TWAMP_CREATE_DEFAULT(&create, &key, &resp);
	dp_test_assert_internal(resp.status < 0);
	dp_test_assert_internal(resp.has_counters == 0);

	json_object *expected = dp_test_json_create(
		"{\"twamp-sessions\":"
		"["
		"{\"local-port\":%d,\"remote-port\":%d,"
		" \"local-address\":\"%s\",\"remote-address\":\"%s\"}"
		"]}",
		lport, rport, laddr.addrstr, raddr.addrstr);
	dp_test_check_json_state("vyatta:twamp dump", expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

	dp_test_twamp_build_counters(&counters, &key, &resp);
	dp_test_assert_internal(resp.status == 0);
	dp_test_assert_internal(resp.has_counters == 1);
	dp_test_assert_internal(resp.tx_pkts == 0);
	dp_test_assert_internal(resp.rx_pkts == 0);

	dp_test_twamp_build_delete(&delete, &key, &resp);
	dp_test_assert_internal(resp.status == 0);
	dp_test_assert_internal(resp.has_counters == 0);

	dp_test_twamp_build_delete(&delete, &key, &resp);
	dp_test_assert_internal(resp.status == 0);
	dp_test_assert_internal(resp.has_counters == 0);

	expected = dp_test_json_create("{\"twamp-sessions\":[]}");
	dp_test_check_json_state("vyatta:twamp dump", expected,
				 DP_TEST_JSON_CHECK_EXACT, false);
	json_object_put(expected);

	dp_test_twamp_build_counters(&counters, &key, &resp);
	dp_test_assert_internal(resp.status < 0);
	dp_test_assert_internal(resp.has_counters == 0);

} DP_END_TEST;

DP_START_TEST(twamp_session, scale)
{
#define SESSION_COUNT 128
	TWAMPSessionCreate create;
	TWAMPSessionDelete delete;
	TWAMPInitialise init;
	TWAMPSessionKey key[SESSION_COUNT];
	struct tw_address laddr[SESSION_COUNT];
	struct tw_address raddr[SESSION_COUNT];
	uint16_t lport = PORT3;
	uint16_t rport = PORT4;
	struct dp_test_twamp_response resp;
	json_object *expected;
	int host;

	for (host = 0; host < SESSION_COUNT; host++) {
		struct tw_address *l = &laddr[host];
		struct tw_address *r = &raddr[host];

		snprintf(l->addrbuf, sizeof(l->addrbuf), "2001:1::%d", host+1);
		snprintf(r->addrbuf, sizeof(r->addrbuf), "2002:2::%d", host+1);
		l->addrstr = l->addrbuf;
		r->addrstr = r->addrbuf;
		dp_test_twamp_build_key(&key[host], l, r, lport, rport);
	}

	for (host = 0; host < SESSION_COUNT; host++) {
		struct tw_address *l = &laddr[host];
		struct tw_address *r = &raddr[host];

		TWAMP_CREATE_DEFAULT(&create, &key[host], &resp);
		dp_test_assert_internal(resp.status == 0);
		dp_test_assert_internal(resp.has_counters == 0);

		expected = dp_test_json_create(
			"{\"twamp-sessions\":"
			"["
			"{\"local-port\":%d,\"remote-port\":%d,"
			" \"local-address\":\"%s\",\"remote-address\":\"%s\"}"
			"]}",
			lport, rport, l->addrstr, r->addrstr);
		dp_test_check_json_state("vyatta:twamp dump", expected,
					 DP_TEST_JSON_CHECK_SUBSET, false);
		json_object_put(expected);
	}

	for (host = 0; host < SESSION_COUNT; host++) {
		dp_test_twamp_build_delete(&delete, &key[host], &resp);
		dp_test_assert_internal(resp.status == 0);
	}

	for (host = 0; host < SESSION_COUNT; host++) {
		TWAMP_CREATE_DEFAULT(&create, &key[host], &resp);
		dp_test_assert_internal(resp.status == 0);
		dp_test_assert_internal(resp.has_counters == 0);
	}

	dp_test_twamp_build_init(&init, NULL, &resp);
	dp_test_assert_internal(resp.status == 0);

	expected = dp_test_json_create("{\"twamp-sessions\":[]}");
	dp_test_check_json_state("vyatta:twamp dump", expected,
				 DP_TEST_JSON_CHECK_EXACT, false);
	json_object_put(expected);
} DP_END_TEST;

DP_START_TEST(twamp_session, ip4createdelete)
{
	TWAMPSessionCreate create;
	TWAMPSessionCounters counters;
	TWAMPSessionDelete delete;
	TWAMPSessionKey key;
	struct tw_address laddr = {
		.addrstr = "9.9.9.9"
	};
	struct tw_address raddr = {
		.addrstr = "8.8.8.8"
	};

	uint16_t lport = PORT1;
	uint16_t rport = PORT2;
	struct dp_test_twamp_response resp;

	dp_test_twamp_build_key(&key, &laddr, &raddr, lport, rport);
	TWAMP_CREATE_DEFAULT(&create, &key, &resp);
	dp_test_assert_internal(resp.status == 0);
	dp_test_assert_internal(resp.has_counters == 0);

	json_object *expected = dp_test_json_create(
		"{\"twamp-sessions\":"
		"["
		"{\"local-port\":%d,\"remote-port\":%d,"
		" \"local-address\":\"%s\",\"remote-address\":\"%s\"}"
		"]}",
		lport, rport, laddr.addrstr, raddr.addrstr);
	dp_test_check_json_state("vyatta:twamp dump", expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

	dp_test_twamp_build_counters(&counters, &key, &resp);
	dp_test_assert_internal(resp.status == 0);
	dp_test_assert_internal(resp.has_counters == 1);
	dp_test_assert_internal(resp.tx_pkts == 0);
	dp_test_assert_internal(resp.rx_pkts == 0);

	dp_test_twamp_build_delete(&delete, &key, &resp);
	dp_test_assert_internal(resp.status == 0);
	dp_test_assert_internal(resp.has_counters == 0);

	expected = dp_test_json_create("{\"twamp-sessions\":[]}");
	dp_test_check_json_state("vyatta:twamp dump", expected,
				 DP_TEST_JSON_CHECK_EXACT, false);
	json_object_put(expected);

	dp_test_twamp_build_counters(&counters, &key, &resp);
	dp_test_assert_internal(resp.status != 0);
	dp_test_assert_internal(resp.has_counters == 0);
	dp_test_twamp_build_delete(&delete, &key, &resp);
	dp_test_assert_internal(resp.status == 0);
	dp_test_assert_internal(resp.has_counters == 0);

	expected = dp_test_json_create("{\"twamp-sessions\":[]}");
	dp_test_check_json_state("vyatta:twamp dump", expected,
				 DP_TEST_JSON_CHECK_EXACT, false);
	json_object_put(expected);

} DP_END_TEST;

DP_START_TEST(twamp_session, ip6createdelete)
{
	TWAMPSessionCreate create;
	TWAMPSessionCounters counters;
	TWAMPSessionDelete delete;
	TWAMPSessionKey key;
	struct tw_address laddr = {
		.addrstr = "2001:1::1"
	};
	struct tw_address raddr = {
		.addrstr = "2001:1::2"
	};
	uint16_t lport = PORT1;
	uint16_t rport = PORT2;
	struct dp_test_twamp_response resp;

	dp_test_twamp_build_key(&key, &laddr, &raddr, lport, rport);
	TWAMP_CREATE_DEFAULT(&create, &key, &resp);
	dp_test_assert_internal(resp.status == 0);
	dp_test_assert_internal(resp.has_counters == 0);

	json_object *expected = dp_test_json_create(
		"{\"twamp-sessions\":"
		"["
		"{\"local-port\":%d,\"remote-port\":%d,"
		" \"local-address\":\"%s\",\"remote-address\":\"%s\"}"
		"]}",
		lport, rport, laddr.addrstr, raddr.addrstr);
	dp_test_check_json_state("vyatta:twamp dump", expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

	dp_test_twamp_build_counters(&counters, &key, &resp);
	dp_test_assert_internal(resp.status == 0);
	dp_test_assert_internal(resp.has_counters == 1);
	dp_test_assert_internal(resp.tx_pkts == 0);
	dp_test_assert_internal(resp.rx_pkts == 0);

	dp_test_twamp_build_delete(&delete, &key, &resp);
	dp_test_assert_internal(resp.status == 0);
	dp_test_assert_internal(resp.has_counters == 0);

	expected = dp_test_json_create("{\"twamp-sessions\":[]}");
	dp_test_check_json_state("vyatta:twamp dump", expected,
				 DP_TEST_JSON_CHECK_EXACT, false);
	json_object_put(expected);

} DP_END_TEST;

DP_DECL_TEST_CASE(twamp_offload_suite, twamp_init, NULL, NULL);

DP_START_TEST(twamp_init, init)
{
	struct dp_test_twamp_response resp;
	TWAMPInitialise init;

	dp_test_check_state_poll_show("vyatta:twamp junk", "", false, false, 1);
	dp_test_check_state_poll_show("vyatta:twamp ", "", false, false, 1);

	dp_test_twamp_build_init(&init, NULL, &resp);
	dp_test_assert_internal(resp.status == 0);

	dp_test_twamp_build_init(&init, "rubbish", &resp);
	dp_test_assert_internal(resp.status < 0);

	dp_test_check_state_show("vyatta:twamp dump", "", true);

	json_object *expected = dp_test_json_create("{\"twamp-sessions\":[]}");
	dp_test_check_json_state("vyatta:twamp dump", expected,
				 DP_TEST_JSON_CHECK_EXACT, false);
	json_object_put(expected);

} DP_END_TEST;
