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
tw_pb_session_delete(TWAMPSessionDelete *delete)
{
	return 0;
}

static int
tw_pb_session_create(TWAMPSessionCreate *create)
{
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
}

void
twamp_init(void)
{
	int rc;

	rc = dp_feature_register_pb_op_handler("vyatta:twamp",
					       tw_protobuf_handler);
	if (rc < 0)
		RTE_LOG(ERR, TWAMP,
			"can not register protobuf handler: %d\n", rc);
}
