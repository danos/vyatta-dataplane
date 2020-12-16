/*
 * Copyright (c) 2020 AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <czmq.h>
#include <libmnl/libmnl.h>
#include <linux/xfrm.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_timer.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config_internal.h"
#include "control.h"
#include "event_internal.h"
#include "controller.h"
#include "netlink.h"
#include "xfrm_client.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "zmq_dp.h"
#include "crypto/crypto_policy.h"
#include "crypto/crypto.h"

zsock_t *xfrm_pull_socket;
zsock_t *xfrm_push_socket;

/*
 * xfrm_direct indcates that xfrm messages are coming direct from
 * strongswan, rather than via vplaned. Updates from vplaned are not
 * batched and do not need to the acked, and the ack channel will not
 * be initialised.
 */
bool xfrm_direct;

uint32_t last_seq_sent;

/*
 * Build a message back to strongswan to indicates if the
 * xfrm message, with sequenece id 'seq', was successfully
 * processed or not.
 *
 * Strongswan expects a netlink error message, and result of the xfrm
 * processing is passed in the error field.
 */
int xfrm_client_send_ack(uint32_t seq, int err)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nlmsgerr *err_msg;
	zframe_t *frame;
	int rc;

	if (!xfrm_direct)
		return 0;
	if (last_seq_sent == seq)
		rte_panic("XFRM Duplicate sequence  %d", seq);

	last_seq_sent = seq;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_seq =  seq;
	nlh->nlmsg_type = NLMSG_ERROR;
	err_msg = mnl_nlmsg_put_extra_header(nlh, sizeof(*err_msg));
	if (!err_msg) {
		DP_DEBUG(CRYPTO, ERR, DATAPLANE,
			 "Failed to alloc xfrm ack error frame\n");
		return -1;
	}

	err_msg->error = (err == MNL_CB_OK) ? 0 : -EPERM;

	frame = zframe_new(nlh, nlh->nlmsg_len);
	if (!frame)
		return -1;

	rc = zframe_send(&frame, xfrm_push_socket, 0);
	if (rc < 0)
		zframe_destroy(&frame);

	return rc;
}

int xfrm_client_send_expire(xfrm_address_t *dst, uint16_t family, uint32_t spi,
			    uint32_t reqid, uint8_t proto, uint8_t hard)
{
	struct xfrm_user_expire *expire;
	struct nlmsghdr *nlh;
	zframe_t *frame;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	int rc;

	memset(buf, 0, MNL_SOCKET_BUFFER_SIZE);

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = XFRM_MSG_EXPIRE;
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_seq = 0;

	expire = mnl_nlmsg_put_extra_header(nlh, sizeof(*expire));
	if (!expire) {
		DP_DEBUG(CRYPTO, ERR, DATAPLANE,
			 "XFRM expire failed SPI:%u\n", spi);
		return -1;
	}

	expire->state.family = family;
	expire->state.id.daddr = *dst;
	expire->state.id.proto = proto;
	expire->state.id.spi = spi;
	expire->state.reqid = reqid;
	expire->hard = hard;

	frame = zframe_new(nlh, nlh->nlmsg_len);
	if (!frame) {
		DP_DEBUG(CRYPTO, ERR, DATAPLANE,
			 "XFRM expire can't create frame SPI:%u\n",
			 spi);
		return -1;
	}

	rc = zframe_send(&frame, xfrm_push_socket, 0);
	if (rc < 0) {
		DP_DEBUG(CRYPTO, ERR, DATAPLANE,
			 "XFRM expire failed to send SPU:%u\n",
			 spi);
		zframe_destroy(&frame);
		return -1;
	}
	return rc;
}
/*
 * Build an SA message back to the server with the stats that were requested.
 */
int xfrm_client_send_sa_stats(uint32_t seq, uint32_t spi,
			      struct crypto_sadb_stats *stats)
{
	struct nlmsghdr *nlh;
	struct xfrm_usersa_info *sa;
	zframe_t *frame;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	int rc;

	memset(buf, 0, MNL_SOCKET_BUFFER_SIZE);

	/* the stats are returned in a NEWSA xfrm which is not intuitive */
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = XFRM_MSG_NEWSA;
	nlh->nlmsg_flags = NLM_F_ACK;
	nlh->nlmsg_seq = seq;

	sa = mnl_nlmsg_put_extra_header(nlh, sizeof(*sa));
	if (!sa) {
		DP_DEBUG(CRYPTO, ERR, DATAPLANE,
			 "XFRM sa stats failed SPI:%u\n", spi);
		return -1;
	}
	sa->curlft.bytes = stats->bytes;
	sa->curlft.packets = stats->packets;

	frame = zframe_new(nlh, nlh->nlmsg_len);
	if (!frame) {
		DP_DEBUG(CRYPTO, ERR, DATAPLANE,
			 "XFRM sa stats framing failed SPI:%u\n", spi);
		return -1;
	}

	rc = zframe_send(&frame, xfrm_push_socket, 0);
	if (rc < 0) {
		DP_DEBUG(CRYPTO, ERR, DATAPLANE,
			 "XFRM sa stats framing failed SPI:%u\n", spi);
		zframe_destroy(&frame);
	}

	return rc;
}

static int
dp_xfrm_msg_recv(zsock_t *sock, zmq_msg_t *hdr, zmq_msg_t *msg)
{
	zmq_msg_init(hdr);
	zmq_msg_init(msg);

	if (zmq_msg_recv(hdr, zsock_resolve(sock), 0) <= 0)
		goto error;

	int more = zmq_msg_get(hdr, ZMQ_MORE);
	if (!more)
		return 0;

	if (zmq_msg_recv(msg, zsock_resolve(sock), 0) <= 0)
		goto error;

	more = zmq_msg_get(msg, ZMQ_MORE);
	while (more) {
		zmq_msg_t sink;
		zmq_msg_init(&sink);
		zmq_msg_recv(&sink, zsock_resolve(sock), 0);
		more = zmq_msg_get(&sink, ZMQ_MORE);
		zmq_msg_close(&sink);
	}

	return 0;
error:
	zmq_msg_close(msg);
	zmq_msg_close(hdr);
	return -1;
}

static int xfrm_netlink_recv(void *arg)
{
	zmq_msg_t xfrm_msg, xfrm_hdr;
	zsock_t *sock = arg;
	const struct nlmsghdr *nlh;
	const char *hdr;
	uint32_t len;
	int rc;
	struct xfrm_client_aux_data xfrm_aux;
	errno = 0;

	rc = dp_xfrm_msg_recv(sock, &xfrm_hdr, &xfrm_msg);

	if (rc != 0) {
		if (errno == 0)
			return 0;
		return -1;
	}

	/*
	 * Get the hdr type, either START, DATA, END and are used to
	 * deliminate a batch. All hdrs have netlink msgs to follow,
	 * however only END is of special significance as it triggers
	 * a npf commit and rebuild.
	 *
	 * The message types of FLUSH and COMMIT are control messages
	 * and used with out any accompanying xfrm.
	 */
	hdr = zmq_msg_data(&xfrm_hdr);
	if (strncmp("FLUSH", hdr, strlen("FLUSH")) == 0) {
		crypto_flush_all();
		goto end;
	} else if (strncmp("COMMIT", hdr, strlen("COMMIT")) == 0) {
		crypto_npf_cfg_commit_flush();
		goto end;
	}

	nlh = zmq_msg_data(&xfrm_msg);
	len = zmq_msg_size(&xfrm_msg);

	if (!nlh || len < sizeof(*nlh)) {
		DP_DEBUG(CRYPTO, ERR, DATAPLANE,
			 "XFRM msg invalid\n");
		goto end;
	}

	vrfid_t vrf_id = VRF_DEFAULT_ID;
	xfrm_aux.vrf = &vrf_id;
	xfrm_aux.seq = nlh->nlmsg_seq;

	switch (nlh->nlmsg_type) {
	case XFRM_MSG_NEWPOLICY: /* Fall through */
	case XFRM_MSG_UPDPOLICY:
	case XFRM_MSG_POLEXPIRE:
	case XFRM_MSG_DELPOLICY:
		/*
		 * Policy updates ACK are normally generated upon the
		 * programming of the policy into the classifier which
		 * occurs at the end of batch. However there are
		 * scenarios when the policy will not be programmed
		 * into the classifier but an ack is still be required
		 * to returned to the xfrm source. These scenarios
		 * include duplicate updates, errors, and incomplete
		 * policies.  Inorder to achieve this a return code
		 * ,rc,and an indication if an ack should be sent
		 * ,xfrm_aux.ack_msg, are required.
		 *
		 * Acks are always sent in error scenarios. However
		 * unless one of the scenarios outlined above are hit
		 * acks are not sent until the policy has been added
		 * to the classifier
		 */
		rc = mnl_cb_run(nlh, len, 0, 0, rtnl_process_xfrm, &xfrm_aux);
		/* Policy acks are batched in most cases */
		if (rc != MNL_CB_OK || xfrm_aux.ack_msg)
			xfrm_client_send_ack(nlh->nlmsg_seq, rc);
		if (strncmp("END", hdr, strlen("END")) == 0)
			crypto_npf_cfg_commit_flush();
		break;

	case XFRM_MSG_NEWSA: /* fall through */
	case XFRM_MSG_UPDSA:
	case XFRM_MSG_DELSA:
	case XFRM_MSG_EXPIRE:
	case XFRM_MSG_GETSA:
		rc = mnl_cb_run(nlh, len, 0, 0, rtnl_process_xfrm_sa,
				&xfrm_aux);
		/*
		 * For all SA messages apart from the GETSA then the
		 * ack response is always sent from here. Successful
		 * GETSA processing generates an message back to the
		 * server and so does not require an ACK, however if
		 * it is unsuccessful an error is sent from here.
		 */
		if (rc != MNL_CB_OK || xfrm_aux.ack_msg)
			xfrm_client_send_ack(nlh->nlmsg_seq, rc);
		break;
	default:
		rc = MNL_CB_ERROR;
		xfrm_client_send_ack(nlh->nlmsg_seq, rc);
	}

	if (rc != MNL_CB_OK) {
		DP_DEBUG(CRYPTO, ERR, DATAPLANE,
			 "XFRM netlink msg not handled\n");
	}
end:
	zmq_msg_close(&xfrm_hdr);
	zmq_msg_close(&xfrm_msg);

	return 0;
}

void xfrm_client_unsubscribe(void)
{
	if (xfrm_push_socket) {
		zsock_destroy(&xfrm_push_socket);
		xfrm_push_socket = NULL;
	}
	if (xfrm_pull_socket) {
		zsock_destroy(&xfrm_pull_socket);
		xfrm_pull_socket = NULL;
	}
}

int xfrm_client_init(void)
{
	/* Ensure we are not restarting  without cleanup */
	if (xfrm_pull_socket || xfrm_push_socket)
		rte_panic("Open xfrm socket");

	if (!config.xfrm_pull_url || !config.xfrm_push_url) {
		RTE_LOG(ERR, DATAPLANE, "No xfrm url");
		/* Once the cut over to the xfrm direct path
		 * is complete need to return -1
		 */
		return 0;
	}

	xfrm_pull_socket = zsock_new(ZMQ_PULL);
	if (!xfrm_pull_socket)
		rte_panic("failed to open xfrm socket");
	if (zsock_connect(xfrm_pull_socket, "%s", config.xfrm_pull_url) < 0)
		rte_panic("failed to open xfrm pull socket");

	xfrm_push_socket = zsock_new(ZMQ_PUSH);
	if (!xfrm_push_socket)
		rte_panic("failed to open xfrm socket");
	if (zsock_connect(xfrm_push_socket, "%s", config.xfrm_push_url) < 0)
		rte_panic("failed to open xfrm push socket");

	dp_register_event_socket(
		zsock_resolve(xfrm_pull_socket),
		xfrm_netlink_recv,
		xfrm_pull_socket);

	xfrm_direct = true;

	return 0;
}
