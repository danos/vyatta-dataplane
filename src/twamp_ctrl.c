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

struct cds_list_head tw_session_list_head =
	CDS_LIST_HEAD_INIT(tw_session_list_head);

static zsock_t *twamp_sock_main;
static zsock_t *twamp_sock_console;

static void tw_main_register_udp_port(uint8_t add, uint8_t af, uint16_t port);

static void
tw_session_udp_port(uint8_t add, uint8_t af, uint16_t port)
{
	if (is_main_thread())
		tw_main_register_udp_port(add, af, port);
	else
		if (zsock_bsend(twamp_sock_console, "112", add, af,
				port) < 0)
			RTE_LOG(ERR, TWAMP,
				"failed to send UDP port details to main\n");
}

static struct tw_session_entry *
tw_session_find(uint16_t lport, uint16_t rport, const struct ip_addr *laddr,
		const struct ip_addr *raddr, vrfid_t vrfid)
{
	struct tw_session_entry *entry;
	cds_list_for_each_entry_rcu(entry, &tw_session_list_head, list)
		if ((entry->session.lport == lport) &&
		    (entry->session.rport == rport) &&
		    (entry->session.vrfid == vrfid) &&
		    dp_addr_eq(&entry->session.laddr, laddr) &&
		    dp_addr_eq(&entry->session.raddr, raddr))
			return entry;

	return NULL;
}

static bool
tw_session_lport_exists(int af, uint16_t lport)
{
	struct tw_session_entry *entry;

	cds_list_for_each_entry_rcu(entry, &tw_session_list_head, list)
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
tw_session_delete(struct tw_session_entry *entry)
{
	if (entry == NULL)
		return;

	cds_list_del(&entry->list);

	if (!tw_session_lport_exists(entry->session.af, entry->session.lport))
		tw_session_udp_port(false, entry->session.af,
				    entry->session.lport);

	call_rcu(&entry->rcu, tw_session_rcu_free);
}

static int
tw_session_clean_vrf(vrfid_t vrfid)
{
	struct tw_session_entry *entry;
	struct tw_session_entry *next;

	cds_list_for_each_entry_safe(entry, next, &tw_session_list_head, list)
		if (entry->session.vrfid == vrfid)
			tw_session_delete(entry);

	return 0;
}

static int
tw_session_clean_all(void)
{
	struct tw_session_entry *entry;
	struct tw_session_entry *next;

	cds_list_for_each_entry_safe(entry, next, &tw_session_list_head, list)
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
static void
tw_main_register_udp_port(uint8_t add, uint8_t af, uint16_t port)
{
	udp_port_handler handler;
	const char *prot;

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
		return;
	}

	if (!add) {
		udp_handler_unregister(af, port);
		DP_DEBUG(TWAMP, INFO, TWAMP,
			 "%s unregistered UDP port %u\n",
			 prot, ntohs(port));
	} else {
		if (udp_handler_register(af, port, handler) != 0)
			RTE_LOG(ERR, TWAMP,
				"failed to register %s UDP port %u\n",
				prot, port);
		else
			DP_DEBUG(TWAMP, INFO, TWAMP,
				 "%s registered UDP port %u\n",
				 prot, ntohs(port));
	}
}

static int
tw_event_register_udp_port(void *arg)
{
	zsock_t *s = arg;
	uint16_t port;
	uint8_t add;
	uint8_t af;

	if (zsock_brecv(s, "112", &add, &af, &port) < 0) {
		RTE_LOG(ERR, TWAMP,
			"failed to receive event for main thread\n");
		return 0;
	}

	tw_main_register_udp_port(add, af, port);
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

	rc = tw_pb_session_key_get(create->key, &lport, &rport,
				   &laddr, &raddr, &vrfid, "create");
	if (rc < 0)
		return rc;

	entry = tw_session_find(lport, rport, &laddr, &raddr, vrfid);
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

	cds_list_add_rcu(&entry->list, &tw_session_list_head);

	if (!port_registered)
		tw_session_udp_port(true, entry->session.af, lport);

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

void
twamp_shutdown(void)
{
	tw_session_clean_all();
	dp_unregister_event_socket(zsock_resolve(twamp_sock_main));
	zsock_destroy(&twamp_sock_main);
	zsock_destroy(&twamp_sock_console);
}

void
twamp_init(void)
{
	int rc;

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

	rc = dp_feature_register_pb_op_handler("vyatta:twamp",
					       tw_protobuf_handler);
	if (rc < 0)
		RTE_LOG(ERR, TWAMP,
			"can not register protobuf handler: %d\n", rc);
}
