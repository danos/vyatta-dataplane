/*-
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * TWAMP dataplane offload; have the dataplane process TWAMP test
 * messages. The main TWAMP daemon is responsible for the TCP-based
 * control session, once negotiation is complete the associated "data
 * channel" (test stream) parameters are packaged up and passed down
 * to the dataplane as a protobuf message.
 *
 * The individual test streams tend to be short-lived, maybe
 * 10s-15s. The protobufs are passed down to the dataplane over the
 * console (as opposed to the control/cstore) channel. As a
 * consequence processing of the protobuf messages is carried out in
 * the context of the console thread, not the master thread.
 *
 * A create message is used to establish the flow (addressing, mode,
 * frame sizes). A counter message is used to request the number of
 * test packets received & reflected back to the client. This is used
 * by the daemon to ensure that the dataplane is making
 * progress. Finally a delete message is used to destroy the flow.
 *
 * See twamp_io.c for the test message formats
 */

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ossl_typ.h>

#include "dp_event.h"
#include "protobuf.h"
#include "protobuf_util.h"
#include "protobuf/TwampResponder.pb-c.h"
#include "vplane_debug.h"
#include "urcu.h"
#include "ip_addr.h"
#include "udp_handler.h"
#include "twamp.h"
#include "twamp_internal.h"

#define TWAMP_TEST_RX_PKT_SIZE_UNAUTH 14
#define TWAMP_TEST_TX_PKT_SIZE_UNAUTH 41
#define TWAMP_TEST_RX_PKT_SIZE_AUTH   48
#define TWAMP_TEST_TX_PKT_SIZE_AUTH   104

#define TWAMP_SESSION_HASH_MIN 16
#define TWAMP_SESSION_HASH_MAX 64

struct tw_hash_key {
	vrfid_t vrfid;
	uint8_t af;
	struct udphdr udp;
	union {
		struct iphdr ip4;
		struct ip6_hdr ip6;
	};
};

struct cds_lfht *tw_session_table;

static zsock_t *twamp_sock_main;
static zsock_t *twamp_sock_console;

static int tw_main_register_udp_port(uint8_t add, uint8_t af, uint16_t port);

static int
tw_session_udp_port(uint8_t add, uint8_t af, uint16_t port)
{
	int rc;

	if (is_main_thread())
		return tw_main_register_udp_port(add, af, port);

	if (zsock_bsend(twamp_sock_console, "112", add, af, port) < 0) {
		RTE_LOG(ERR, TWAMP,
			"failed to send UDP port details to main\n");
		return -EIO;
	}

	if (zsock_recv(twamp_sock_console, "i", &rc) < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"failed to get UDP port response from main\n");
		return -EIO;
	}

	return rc;
}

/*
 * Using the addressing details that have been extracted from the PB
 * message, build fake UDP & IP headers. This allows for hashing &
 * matching functions to be shared between control & data.
 */
static uint32_t
tw_session_hash(uint16_t lport, uint16_t rport, const struct ip_addr *laddr,
		const struct ip_addr *raddr, vrfid_t vrfid,
		struct tw_hash_key *hkey)
{
	memset(hkey, 0, sizeof(*hkey));
	hkey->vrfid = vrfid;
	hkey->udp.source = rport;
	hkey->udp.dest = lport;
	hkey->af = laddr->type;
	switch (hkey->af) {
	case AF_INET:
		hkey->ip4.saddr = raddr->address.ip_v4.s_addr;
		hkey->ip4.daddr = laddr->address.ip_v4.s_addr;
		return twamp_hash_ipv4(hkey->vrfid, &hkey->ip4, &hkey->udp);
	case AF_INET6:
		memcpy(&hkey->ip6.ip6_src.s6_addr,
		       &raddr->address.ip_v6.s6_addr,
		       sizeof(hkey->ip6.ip6_src));
		memcpy(&hkey->ip6.ip6_dst.s6_addr,
		       &laddr->address.ip_v6.s6_addr,
		       sizeof(hkey->ip6.ip6_dst));
		return twamp_hash_ipv6(hkey->vrfid, &hkey->ip6, &hkey->udp);
	default:
		rte_panic("unknown address family: %u\n", hkey->af);
		break;
	}

	return 0;
}

static int
tw_session_match(struct cds_lfht_node *node, const void *arg)
{
	const struct tw_hash_key *hkey = arg;
	struct tw_hash_match_args match = {
		.vrfid = hkey->vrfid,
		.udp = &hkey->udp,
	};

	switch (hkey->af) {
	case AF_INET:
		match.ip4 = &hkey->ip4;
		return twamp_hash_match_ipv4(node, &match);
	case AF_INET6:
		match.ip6 = &hkey->ip6;
		return twamp_hash_match_ipv6(node, &match);
	default:
		rte_panic("unknown address family: %u\n", hkey->af);
		break;
	}

	return 1;
}

static struct tw_session_entry *
tw_session_find(uint16_t lport, uint16_t rport, const struct ip_addr *laddr,
		const struct ip_addr *raddr, vrfid_t vrfid, uint32_t *hashp)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct tw_hash_key hkey;
	uint32_t hash;

	hash = tw_session_hash(lport, rport, laddr, raddr, vrfid, &hkey);
	if (hashp != NULL)
		*hashp = hash;

	cds_lfht_lookup(tw_session_table, hash, tw_session_match, &hkey, &iter);
	node = cds_lfht_iter_get_node(&iter);
	if (node != NULL)
		return caa_container_of(node, struct tw_session_entry, tw_node);

	return NULL;
}

static bool
tw_session_lport_exists(int af, uint16_t lport)
{
	struct tw_session_entry *entry;
	struct cds_lfht_iter iter;

	cds_lfht_for_each_entry(tw_session_table, &iter, entry, tw_node)
		if ((entry->session.af == af) &&
		    (entry->session.lport == lport))
			return true;

	return false;
}

static void
tw_session_free(struct tw_session_entry *entry)
{
	free(entry);
}

static void
tw_session_rcu_free(struct rcu_head *rcuhead)
{
	struct tw_session_entry *entry;

	entry = caa_container_of(rcuhead, struct tw_session_entry, rcu);
	tw_session_free(entry);
}

static void
tw_session_delete_port_check(struct tw_session_entry *entry,
			     bool port_check)
{
	if (entry == NULL)
		return;

	cds_lfht_del(tw_session_table, &entry->tw_node);

	if (port_check &&
	    !tw_session_lport_exists(entry->session.af, entry->session.lport))
		tw_session_udp_port(false, entry->session.af,
				    entry->session.lport);

	call_rcu(&entry->rcu, tw_session_rcu_free);
}

static void
tw_session_delete(struct tw_session_entry *entry)
{
	tw_session_delete_port_check(entry, true);
}

static int
tw_session_clean_vrf(vrfid_t vrfid)
{
	struct tw_session_entry *entry;
	struct cds_lfht_iter iter;

	cds_lfht_for_each_entry(tw_session_table, &iter, entry, tw_node)
		if (entry->session.vrfid == vrfid)
			tw_session_delete(entry);

	return 0;
}

static int
tw_session_clean_all(void)
{
	struct tw_session_entry *entry;
	struct cds_lfht_iter iter;

	cds_lfht_for_each_entry(tw_session_table, &iter, entry, tw_node)
		tw_session_delete(entry);

	return 0;
}

static struct tw_session_entry *
tw_session_create(uint16_t lport, uint16_t rport, const struct ip_addr *laddr,
		  const struct ip_addr *raddr, vrfid_t vrfid)
{
	struct tw_session_entry *entry;

	entry = calloc(1, sizeof(*entry));
	if (entry != NULL) {
		entry->session.lport = lport;
		entry->session.rport = rport;
		entry->session.vrfid = vrfid;
		entry->session.laddr = *laddr;
		entry->session.raddr = *raddr;
		entry->session.af = laddr->type;
		if (entry->session.af == AF_INET)
			entry->session.dbgstr = "IPv4";
		else if (entry->session.af == AF_INET6)
			entry->session.dbgstr = "IPv6";
		else {
			RTE_LOG(ERR, TWAMP, "unknown address family (%u)\n",
				entry->session.af);
			free(entry);
			return NULL;
		}
	}

	return entry;
}

static const char *
tw_ip2str(const struct ip_addr *addr, char *buf, size_t len)
{
	return inet_ntop(addr->type, &addr->address, buf, len);
}

/*
 * Register the IPv4/IPv6 UDP destination port with the main UDP
 * dispatch component. This needs to occur on the master thread.
 */
static int
tw_main_register_udp_port(uint8_t add, uint8_t af, uint16_t port)
{
	udp_port_handler handler;
	const char *prot;
	int rc;

	switch (af) {
	case AF_INET:
		handler = twamp_input_ipv4;
		prot = "IPv4";
		break;
	case AF_INET6:
		handler = twamp_input_ipv6;
		prot = "IPv6";
		break;
	default:
		RTE_LOG(ERR, TWAMP,
			"unknown address family for main event: %u\n",
			af);
		return -EPROTO;
	}

	if (!add) {
		udp_handler_unregister(af, port);
		DP_DEBUG(TWAMP, INFO, TWAMP,
			 "%s unregistered UDP port %u\n",
			 prot, ntohs(port));
		return 0;
	}

	rc = udp_handler_register(af, port, handler);
	if (rc < 0)
		RTE_LOG(ERR, TWAMP,
			"failed to register %s UDP port %u ('%s')\n",
			prot, ntohs(port), strerror(-rc));
	else
		DP_DEBUG(TWAMP, INFO, TWAMP,
			 "%s registered UDP port %u\n",
			 prot, ntohs(port));

	return rc;
}

static int
tw_event_register_udp_port(void *arg)
{
	zsock_t *s = arg;
	uint16_t port;
	uint8_t add;
	uint8_t af;
	int rc;

	if (zsock_brecv(s, "112", &add, &af, &port) < 0) {
		RTE_LOG(ERR, TWAMP,
			"failed to receive event for main thread\n");
		return 0;
	}

	rc = tw_main_register_udp_port(add, af, port);

	if (zsock_send(s, "i", rc) < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"failed to send response to main thread\n");
		return -EIO;
	}

	return 0;
}

static int
tw_session_dump(FILE *f)
{
	struct tw_session_entry *entry;
	struct cds_lfht_iter iter;
	json_writer_t *wr;
	char b1[INET6_ADDRSTRLEN];

	wr = jsonw_new(f);
	jsonw_name(wr, "twamp-sessions");
	jsonw_start_array(wr);

	cds_lfht_for_each_entry(tw_session_table, &iter, entry, tw_node) {
		const struct tw_session *tws = &entry->session;
		const char *mode;

		switch (entry->session.mode) {
		case TWAMPSESSION_CREATE__MODE__MODE_OPEN:
			mode = "open";
			break;
		case TWAMPSESSION_CREATE__MODE__MODE_AUTHENTICATED:
			mode = "authenticated";
			break;
		case TWAMPSESSION_CREATE__MODE__MODE_ENCRYPTED:
			mode = "encrypted";
			break;
		default:
			mode = "???";
			break;
		}

		jsonw_start_object(wr);
		jsonw_uint_field(wr, "local-port", ntohs(tws->lport));
		jsonw_uint_field(wr, "remote-port", ntohs(tws->rport));
		jsonw_string_field(wr, "local-address",
				   tw_ip2str(&tws->laddr, b1, sizeof(b1)));
		jsonw_string_field(wr, "remote-address",
				   tw_ip2str(&tws->raddr, b1, sizeof(b1)));
		jsonw_string_field(wr, "mode", mode);
		jsonw_uint_field(wr, "rx-pkts", tws->rx_pkts);
		jsonw_uint_field(wr, "rx-bad-pkts", tws->rx_bad);
		jsonw_uint_field(wr, "tx-pkts", tws->tx_pkts);
		jsonw_uint_field(wr, "tx-bad-pkts", tws->tx_bad);
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);
	jsonw_destroy(&wr);
	return 0;
}

static int
tw_get_vrf(const char *vrf_name, vrfid_t *vrfid)
{
	struct vrf *vrf;
	vrfid_t id;

	if (vrf_name == NULL) {
		*vrfid = VRF_DEFAULT_ID;
		return 0;
	}

	VRF_FOREACH(vrf, id) {
		if (streq(vrf->v_name, vrf_name)) {
			*vrfid = id;
			return 0;
		}
	}

	return -ENOENT;
}

static int
tw_pb_session_key_get(TWAMPSessionKey *key, uint16_t *lport, uint16_t *rport,
		      struct ip_addr *laddr, struct ip_addr *raddr,
		      vrfid_t *vrf_id, const char *who)
{
	int rc = 0;

	*lport = htons(key->lport);
	*rport = htons(key->rport);

	if (dp_protobuf_get_ipaddr(key->laddr, laddr) < 0)
		rc = -EINVAL;

	if (rc == 0)
		if (dp_protobuf_get_ipaddr(key->raddr, raddr) < 0)
			rc = -EINVAL;

	if (rc == 0)
		if (laddr->type != raddr->type)
			rc = -EPROTO;

	if (rc == 0)
		rc = tw_get_vrf(key->vrf_name, vrf_id);

	if (rc < 0) {
		DP_DEBUG(TWAMP, ERR, TWAMP,
			 "failed to extract PB %s key: %s\n",
			 who, strerror(-rc));
		return rc;
	}

	return 0;
}

static int
tw_pb_session_delete(TWAMPSessionDelete *delete)
{
	struct tw_session_entry *entry;
	struct ip_addr laddr;
	struct ip_addr raddr;
	uint16_t lport;
	uint16_t rport;
	vrfid_t vrfid;

	if (tw_pb_session_key_get(delete->key, &lport, &rport,
				  &laddr, &raddr, &vrfid, "delete") < 0) {
		return -1;
	}

	entry = tw_session_find(lport, rport, &laddr, &raddr, vrfid, NULL);
	if (entry == NULL) {
		DP_DEBUG(TWAMP, DEBUG, TWAMP,
			 "session delete failed: not found\n");
		return 0;
	}

	char b1[INET6_ADDRSTRLEN];
	char b2[INET6_ADDRSTRLEN];

	DP_DEBUG(TWAMP, INFO, TWAMP,
		"session deleted %s:%u -> %s:%u (tx %lu rx %lu)\n",
		tw_ip2str(&raddr, b1, sizeof(b1)), ntohs(rport),
		tw_ip2str(&laddr, b2, sizeof(b2)), ntohs(lport),
		entry->session.tx_pkts, entry->session.rx_pkts);

	tw_session_delete(entry);
	return 0;
}

static int
tw_pb_session_create_crypto(TWAMPSessionCreate *create __unused,
			    struct tw_session_entry *entry __unused)
{
	return -ENOTSUP;
}

static int
tw_pb_session_create(TWAMPSessionCreate *create)
{
	struct tw_session_entry *entry;
	struct ip_addr laddr;
	struct ip_addr raddr;
	uint16_t lport;
	uint16_t rport;
	vrfid_t vrfid;
	bool port_registered;
	const char *mode;
	char b1[INET6_ADDRSTRLEN];
	char b2[INET6_ADDRSTRLEN];
	int rc;
	uint32_t hash;

	rc = tw_pb_session_key_get(create->key, &lport, &rport,
				   &laddr, &raddr, &vrfid, "create");
	if (rc < 0)
		return rc;

	entry = tw_session_find(lport, rport, &laddr, &raddr, vrfid, &hash);
	if (entry != NULL) {
		RTE_LOG(ERR, TWAMP,
			"session create (%s:%u -> %s:%u) failed: exists\n",
			tw_ip2str(&raddr, b1, sizeof(b1)), ntohs(rport),
			tw_ip2str(&laddr, b2, sizeof(b2)), ntohs(lport));
		return -EEXIST;
	}

	entry = tw_session_create(lport, rport, &laddr, &raddr, vrfid);
	if (entry == NULL)
		return -ENOMEM;

	entry->session.mode = create->mode;
	switch (entry->session.mode) {
	case TWAMPSESSION_CREATE__MODE__MODE_OPEN:
		entry->session.minrxpktsize = TWAMP_TEST_RX_PKT_SIZE_UNAUTH;
		entry->session.mintxpktsize = TWAMP_TEST_TX_PKT_SIZE_UNAUTH;
		mode = "open";
		break;
	case TWAMPSESSION_CREATE__MODE__MODE_AUTHENTICATED:
		entry->session.minrxpktsize = TWAMP_TEST_RX_PKT_SIZE_AUTH;
		entry->session.mintxpktsize = TWAMP_TEST_TX_PKT_SIZE_AUTH;
		mode = "authenticated";
		break;
	case TWAMPSESSION_CREATE__MODE__MODE_ENCRYPTED:
		entry->session.minrxpktsize = TWAMP_TEST_RX_PKT_SIZE_AUTH;
		entry->session.mintxpktsize = TWAMP_TEST_TX_PKT_SIZE_AUTH;
		mode = "encrypted";
		break;
	default:
		tw_session_delete(entry);
		RTE_LOG(ERR, TWAMP,
			"%s session create failed: unknown mode %u\n",
			entry->session.dbgstr, entry->session.mode);
		return -EINVAL;
	}

	entry->session.rxpayloadlen = create->rx_payload_len;
	entry->session.txpayloadlen = create->tx_payload_len;

	if (entry->session.mode != TWAMPSESSION_CREATE__MODE__MODE_OPEN) {
		int rc;

		rc = tw_pb_session_create_crypto(create, entry);
		if (rc < 0) {
			RTE_LOG(ERR, TWAMP,
				"%s session create (%s:%u -> %s:%u) failed: %s\n",
				mode,
				tw_ip2str(&raddr, b1, sizeof(b1)), ntohs(rport),
				tw_ip2str(&laddr, b2, sizeof(b2)), ntohs(lport),
				strerror(-rc));
			tw_session_free(entry);
			return rc;
		}
	}

	port_registered = tw_session_lport_exists(entry->session.af, lport);

	cds_lfht_add(tw_session_table, hash, &entry->tw_node);

	if (!port_registered) {
		rc = tw_session_udp_port(true, entry->session.af, lport);
		if (rc < 0) {
			tw_session_delete_port_check(entry, false);
			return rc;
		}
	}

	DP_DEBUG(TWAMP, INFO, TWAMP,
		 "%s session created %s:%u -> %s:%u payload size %u %u\n",
		 mode,
		 tw_ip2str(&raddr, b1, sizeof(b1)), ntohs(rport),
		 tw_ip2str(&laddr, b2, sizeof(b2)), ntohs(lport),
		 entry->session.rxpayloadlen, entry->session.txpayloadlen);

	return 0;
}

static int
tw_pb_session_counters(TWAMPSessionCounters *counters,
		       TWAMPSessionCounterResponse *resp)
{
	struct tw_session_entry *entry;
	struct ip_addr laddr;
	struct ip_addr raddr;
	uint16_t lport;
	uint16_t rport;
	vrfid_t vrfid;

	if (tw_pb_session_key_get(counters->key, &lport, &rport,
				  &laddr, &raddr, &vrfid, "counter") < 0) {
		return -1;
	}

	entry = tw_session_find(lport, rport, &laddr, &raddr, vrfid, NULL);
	if (entry == NULL) {
		DP_DEBUG(TWAMP, DEBUG, TWAMP,
			 "session counters failed: not found\n");
		return -1;
	}

	resp->has_rx_pkts = true;
	resp->rx_pkts = entry->session.rx_pkts;
	resp->has_rx_bad = true;
	resp->rx_bad = entry->session.rx_bad;
	resp->has_tx_pkts = true;
	resp->tx_pkts = entry->session.tx_pkts;
	resp->has_tx_bad = true;
	resp->tx_bad = entry->session.tx_bad;
	return 0;
}

static int
tw_pb_init(TWAMPInitialise *init)
{
	const char *vrfname = init->vrf_name;
	vrfid_t vrfid;
	int rc;

	if (vrfname == NULL)
		vrfname = "DEFAULT";

	rc = tw_get_vrf(init->vrf_name, &vrfid);
	if (rc < 0) {
		DP_DEBUG(TWAMP, ERR, TWAMP,
			 "initialisation VRF '%s' failed: %s\n",
			 vrfname, strerror(-rc));
		return rc;
	}

	DP_DEBUG(TWAMP, INFO, TWAMP,
		 "initialisation VRF '%s'\n", vrfname);
	tw_session_clean_vrf(vrfid);
	return 0;
}

static int
tw_protobuf_handler(struct pb_msg *msg)
{
	TWAMPCmd *cmd = twampcmd__unpack(NULL, msg->msg_len, msg->msg);
	TWAMPCmdResponse resp = TWAMPCMD_RESPONSE__INIT;
	TWAMPSessionCounterResponse cntrresp =
		TWAMPSESSION_COUNTER_RESPONSE__INIT;
	int rc = -1;

	switch (cmd->mtype_case) {
	case TWAMPCMD__MTYPE_TW_INIT:
		rc = tw_pb_init(cmd->tw_init);
		break;
	case TWAMPCMD__MTYPE_TWS_DELETE:
		rc = tw_pb_session_delete(cmd->tws_delete);
		break;
	case TWAMPCMD__MTYPE_TWS_CREATE:
		rc = tw_pb_session_create(cmd->tws_create);
		break;
	case TWAMPCMD__MTYPE_TWS_COUNTERS:
		rc = tw_pb_session_counters(cmd->tws_counters, &cntrresp);
		if (rc == 0)
			resp.counters = &cntrresp;
		break;
	default:
		RTE_LOG(ERR, TWAMP,
			"unknown message type %d\n", cmd->mtype_case);
		break;
	}

	twampcmd__free_unpacked(cmd, NULL);

	resp.status = rc;
	resp.has_status = true;
	size_t len = twampcmd_response__get_packed_size(&resp);
	void *buf = malloc(len);
	twampcmd_response__pack(&resp, buf);
	msg->ret_msg = buf;
	msg->ret_msg_len = len;
	return 0;
}

static int
tw_server_ops(FILE *f, int argc, char **argv)
{
	if (argc != 2)
		return -EINVAL;

	if (streq(argv[1], "dump"))
		return tw_session_dump(f);

	fprintf(f, "Usage: vyatta:twamp dump");
	return -EINVAL;
}

void
twamp_shutdown(void)
{
	tw_session_clean_all();
	dp_unregister_event_socket(zsock_resolve(twamp_sock_main));
	zsock_destroy(&twamp_sock_main);
	zsock_destroy(&twamp_sock_console);
	cds_lfht_destroy(tw_session_table, NULL);
}

void
twamp_init(void)
{
	int rc;

	tw_session_table = cds_lfht_new(TWAMP_SESSION_HASH_MIN,
					TWAMP_SESSION_HASH_MIN,
					TWAMP_SESSION_HASH_MAX,
					CDS_LFHT_AUTO_RESIZE,
					NULL);
	if (tw_session_table == NULL)
		rte_panic("twamp session table failed\n");

	twamp_sock_main = zsock_new_pair("@inproc://twamp_main_event");
	if (twamp_sock_main == NULL)
		rte_panic("twamp main socket failed\n");

	twamp_sock_console = zsock_new_pair(">inproc://twamp_main_event");
	if (twamp_sock_console == NULL)
		rte_panic("twamp console socket failed\n");

	if (dp_register_event_socket(zsock_resolve(twamp_sock_main),
				     tw_event_register_udp_port,
				     twamp_sock_main) < 0)
		rte_panic("cannot registration UDP port handler\n");

	rc = dp_feature_register_string_op_handler("vyatta:twamp",
						   "TWAMP server control",
						   tw_server_ops);
	if (rc < 0)
		RTE_LOG(ERR, TWAMP,
			"can not register op-mode handler: %d\n", rc);

	rc = dp_feature_register_pb_op_handler("vyatta:twamp",
					       tw_protobuf_handler);
	if (rc < 0)
		RTE_LOG(ERR, TWAMP,
			"can not register protobuf handler: %d\n", rc);
}
