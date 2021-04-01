/*
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2014-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * NPF ALG for RPC
 */

#include <errno.h>
#include <netinet/in.h>
#include <rpc/pmap_prot.h>
#include <rpc/rpc_msg.h>
#include <rte_log.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <urcu/list.h>

#include "compiler.h"
#include "npf/npf.h"
#include "npf/alg/alg.h"
#include "npf/alg/alg_session.h"
#include "npf/alg/alg_rpc_msg.h"
#include "npf/npf_cache.h"
#include "npf/npf_nat.h"
#include "npf/npf_session.h"
#include "urcu.h"
#include "util.h"
#include "vplane_log.h"
#include "npf/alg/alg_rpc.h"

struct ifnet;
struct rte_mbuf;

#define RPC_MAX_PORT 65535

/* Skip over words in an rpc msg */
#define SKIP(a, b) ((uint32_t *)((uint8_t *)(a) + (b)))

#define RPC_PORT_CONFIG 0
#define RPC_PROG_CONFIG 1

/* Payload buffer sizes */
#define RPC_MIN_LENGTH 28
#define RPC_MAX_LENGTH 256

/*
 * RPC ALG session flags (sa_flags, struct npf_session_alg)
 *
 * Also used in tuple flags (at_client_flags, struct apt_tuple)
 *
 * Least significant byte indicates flow type, of which lower nibble is
 * control flow types and upper nibble is data flow types.
 */
#define RPC_ALG_CNTL	0x0001
#define RPC_ALG_DATA	0x0010

static_assert((RPC_ALG_CNTL & ALG_MASK_CNTL_FLOW) != 0,
	      "RPC_ALG_CNTL error");
static_assert((RPC_ALG_DATA & ALG_MASK_DATA_FLOW) != 0,
	      "RPC_ALG_DATA error");


/*
 * Used to ensure not reading more bytes than was in the packet.
 *
 * It compares the field which is about to be read with the end
 * of the packet, to ensure it will not read past the end of the packet.
 */
#define RPC_PKT_EXCEEDED(read_pos, field_size, buf_start, rpc_len) \
	(((uint8_t *)(read_pos)) + (field_size) > (buf_start) + (rpc_len))

/* Struct for maintaining configured RPC program #'s */
struct rpc_node {
	uint32_t		rpc_program;	/* Configured rpc content */
	struct cds_list_head	list;		/* list head */
	struct rcu_head		rcu_head;	/* For call_rcu() */
};

struct rpc_private {
	struct cds_list_head rpc_lh;
};

static void rpc_free_node(struct rcu_head *head)
{
	struct rpc_node *node =
			caa_container_of(head, struct rpc_node, rcu_head);
	free(node);
}

/* Delete a rpc program from configuration */
static int rpc_program_delete(struct npf_alg *rpc, uint32_t program)
{
	struct rpc_node *node, *node2;
	int ret = -ENOENT;
	struct rpc_private *rp = rpc->na_private;

	if (!rp)
		return -EINVAL;

	cds_list_for_each_entry_safe(node, node2, &rp->rpc_lh, list) {
		if (node->rpc_program == program) {
			cds_list_del_rcu(&node->list);
			call_rcu(&node->rcu_head, rpc_free_node);
			ret = 0;
		}
	}

	return ret;
}

/* Destroy all programs */
static void rpc_destroy_list(struct npf_alg *rpc)
{
	struct rpc_node *node, *node2;
	struct rpc_private *rp = rpc->na_private;

	if (!rp)
		return;

	cds_list_for_each_entry_safe(node, node2, &rp->rpc_lh, list) {
		cds_list_del_rcu(&node->list);
		call_rcu(&node->rcu_head, rpc_free_node);
	}
}


/* Lookup a RPC program in configuration */
static int rpc_program_exists(struct npf_alg *rpc, uint32_t program)
{
	struct rpc_node *node;
	struct rpc_private *rp = rpc->na_private;

	if (!rp)
		return 0;

	cds_list_for_each_entry_rcu(node, &rp->rpc_lh, list)
		if (node->rpc_program == program)
			return 1;
	return 0;
}

/* Add an RPC program to the configuration */
static int rpc_program_add(struct npf_alg *rpc, uint32_t program)
{
	struct rpc_node *node;
	struct rpc_private *rp = rpc->na_private;

	if (rpc_program_exists(rpc, program))
		return -1;

	if (!rp)
		return -EINVAL;

	node = malloc(sizeof(struct rpc_node));
	if (!node)
		return -ENOMEM;
	node->rpc_program = program;
	cds_list_add_tail_rcu(&node->list, &rp->rpc_lh);
	return 0;
}

/* Manage a default config program item */
static int rpc_alg_program_handler(struct npf_alg *rpc, int op,
		const struct npf_alg_config_item *ci)
{
	int rc;

	switch (op) {
	case NPF_ALG_CONFIG_DELETE:
		rc = rpc_program_delete(rpc, ci->ci_datum);
		break;
	case NPF_ALG_CONFIG_SET:
		rc = rpc_program_add(rpc, ci->ci_datum);
		break;
	default:
		rc = -EINVAL;
	}
	if (rc)
		RTE_LOG(ERR, FIREWALL, "ALG: RPC: program manage: %d\n", rc);
	return rc;
}


/* Insert a tuple */
static int rpc_tuple_insert(struct npf_alg *rpc,
			    npf_cache_t *npc, npf_session_t *se,
			    const npf_addr_t *srcip,
			    const npf_addr_t *dstip, uint16_t dport)
{
	struct apt_match_key m = { 0 };
	struct apt_tuple *at;

	m.m_proto = npf_cache_ipproto(npc);
	m.m_ifx = npf_session_get_if_index(se);
	m.m_alen = npc->npc_alen;
	m.m_dport = dport;
	m.m_sport = 0;
	m.m_dstip = dstip;
	m.m_srcip = srcip;
	m.m_match = APT_MATCH_ANY_SPORT;

	at = apt_tuple_create_and_insert(rpc->na_ai->ai_apt, &m,
					 npf_alg_get(rpc),
					 0, NPF_ALG_RPC_NAME,
					 true, false);

	if (!at) {
		npf_alg_put(rpc);
		RTE_LOG(ERR, FIREWALL, "RPC: tuple insert\n");
		return -EINVAL;
	}
	apt_tuple_set_session(at, se);

	return 0;
}

/* Parse a RPC request msg */
static int rpc_parse_request(struct rpc_request *rr, uint32_t xid,
			     uint32_t *rpc_data, const uint8_t *buf_start,
			     uint32_t rpc_len)
{
	uint32_t field_len;

	rr->rr_xid = xid;
	rr->rr_rpc_version = ntohl(*rpc_data++); /* version */
	rr->rr_program = ntohl(*rpc_data++);
	rr->rr_program_version = ntohl(*rpc_data++);
	rr->rr_procedure = ntohl(*rpc_data++);

	rpc_data++;	/* skip cred flavor */

	/* determine length of cred flavor and skip */
	field_len = ntohl(*rpc_data++);

	/* Must be a integral number of 4b words */
	if ((field_len & 3) != 0)
		return -EINVAL;

	if (RPC_PKT_EXCEEDED(rpc_data, field_len, buf_start, rpc_len))
		return -EINVAL;

	rpc_data = SKIP(rpc_data, field_len);

	rpc_data++;	/* skip verifier flavor */

	/* determine length of verifier flavor and skip */
	field_len = ntohl(*rpc_data++);

	/* Must be a integral number of 4b words */
	if ((field_len & 3) != 0)
		return -EINVAL;

	if (RPC_PKT_EXCEEDED(rpc_data, field_len, buf_start, rpc_len))
		return -EINVAL;

	rpc_data = SKIP(rpc_data, field_len);

	if (RPC_PKT_EXCEEDED(rpc_data, 4, buf_start, rpc_len))
		return -EINVAL;
	rr->rr_pmap_program = ntohl(*rpc_data);

	return 0;
}

static int rpc_verify_request(struct npf_alg *rpc, struct rpc_request *rr)
{
	if (!rr->rr_xid)
		return -EINVAL;

	if (rr->rr_rpc_version != RPC_MSG_VERSION)
		return -EINVAL;

	/* Only portmap with getproc needs handled. */
	if (!(rr->rr_program == PMAPPROG &&
	    rr->rr_procedure == PMAPPROC_GETPORT))
		return -EINVAL;

	/* Verify program is in the list to do the ALG for */
	if (!rpc_program_exists(rpc, rr->rr_pmap_program))
		return -EINVAL;

	return 0;
}

/* Parse a RPC reply msg */
static int rpc_parse_reply(struct rpc_request *rr, struct rpc_reply *rp,
			   uint32_t *rpc_data, uint32_t xid,
			   const uint8_t *buf_start, uint32_t rpc_len)
{
	uint32_t field_len;

	rp->rp_xid = xid;
	rp->rp_reply_state = ntohl(*rpc_data++);
	rpc_data++; /* Skip auth */

	/* determine length of auth response and skip */
	field_len = ntohl(*rpc_data++);

	/* Must be a integral number of 4b words */
	if ((field_len & 3) != 0)
		return -EINVAL;

	/* If we will exceed the buffer, abort */
	if (RPC_PKT_EXCEEDED(rpc_data, field_len, buf_start, rpc_len))
		return -EINVAL;

	rpc_data = SKIP(rpc_data, field_len);

	if (RPC_PKT_EXCEEDED(rpc_data, 4, buf_start, rpc_len))
		return -EINVAL;
	rp->rp_accept_state = ntohl(*rpc_data++);

	/* Only for port mapper */
	if (rr->rr_program == PMAPPROG &&
	    rr->rr_procedure == PMAPPROC_GETPORT) {
		if (RPC_PKT_EXCEEDED(rpc_data, 4, buf_start, rpc_len))
			return -EINVAL;
		rp->rp_port = ntohl(*rpc_data); /* host order for now */
	} else
		rp->rp_port = 0;

	return 0;
}

/* Manage the RPC request */
static int rpc_manage_request(npf_session_t *se, uint32_t xid,
		uint32_t *rpc_data, uint8_t *buf_start, uint32_t rpc_len)
{
	int rc;
	struct rpc_request *rr;
	struct npf_alg *rpc;
	struct npf_session_alg *sa;

	/* Get ALG session data */
	sa = npf_session_get_alg_ptr(se);
	if (!sa)
		return -ENOENT;

	rpc = sa->sa_alg;
	rr = &sa->sa_rpc.sar_request;

	/*
	 * Populate the ALG session data with the objects from the RPC Request
	 * msg that we are interested in.  Note that retransmissions may
	 * occur, and it is ok if we overwrite existing values.
	 *
	 * These saved values will be matched to the RCP Reply message.
	 */
	rc = rpc_parse_request(rr, xid, rpc_data, buf_start, rpc_len);
	if (rc < 0) {
		rr->rr_xid = 0; /* Invalidate the stored request data */
		return rc;
	}

	rc = rpc_verify_request(rpc, rr);
	if (rc) {
		rr->rr_xid = 0; /* Invalidate the stored request data */
		return rc;
	}

	return 0;
}

/* Manage reply */
static int rpc_manage_reply(npf_session_t *se, uint32_t xid, uint32_t *rpc_data,
			    in_port_t *port, uint8_t *buf_start,
			    uint32_t rpc_len)
{
	int rc = 0;
	struct rpc_reply rp;
	struct rpc_request *rr;
	struct npf_session_alg *sa;

	/* Get ALG session data */
	sa = npf_session_get_alg_ptr(se);
	if (!sa)
		return -ENOENT;

	/*
	 * The ALG session data should have valid Request params saved from an
	 * earlier Request msg.
	 */
	rr = &sa->sa_rpc.sar_request;
	if (!rr->rr_xid)
		return -ENOENT;

	rc = rpc_parse_reply(rr, &rp, rpc_data, xid, buf_start, rpc_len);
	if (rc < 0)
		goto done;

	if (rr->rr_xid != rp.rp_xid) {
		rc = -EINVAL;
		goto done;
	}

	/* We are only interested in valid rpc completions */
	if (rp.rp_reply_state != MSG_ACCEPTED)
		goto done;

	if (rp.rp_accept_state != SUCCESS)
		goto done;

	/*
	 * We are only interested in portmapper GETPORTs. So ensure
	 * that we only add a tuple if we get a port from it.
	 */
	if (rr->rr_procedure == PMAPPROC_GETPORT && rp.rp_port) {
		if (rp.rp_port > RPC_MAX_PORT) {
			rc = -EINVAL;
			goto done;
		}
		*port = (in_port_t) htons(rp.rp_port);
	} else
		*port = 0;

	/*
	 * If we received a successful reply, stop parsing
	 * rpc packets on this session handle.
	 *
	 * Note that we have parsed the first RPC packets for all
	 * enabled rpc programs.
	 */
	npf_nat_t *nat = npf_session_get_nat(se);
	/*
	 * Must only clear the ALG field of NAT if NAT is running on
	 * this session.
	 */
	if (nat)
		npf_nat_setalg(nat, NULL);
	npf_alg_session_set_inspect(se, false);

done:
	/* Invalidate the stored request data */
	rr->rr_xid = 0;
	return rc;
}

/*
 * parse_portmap packet() - parse portmap request/reply packets.
 */
static int rpc_parse_packet(npf_cache_t *npc, npf_session_t *se,
		struct rte_mbuf *nbuf, uint16_t *port)
{
	uint32_t len;
	uint32_t rc;
	uint32_t type;
	uint32_t xid;
	uint8_t rpc_buf[RPC_MAX_LENGTH];

	/*
	 * rpc_buf is larger than any rpc msg fields we are interested in.
	 * We will detect invalid packets as we can.
	 *
	 * Note we are not interested in the complete rpc msg, only
	 * the start of it.
	 */

	len = npf_payload_fetch(npc, nbuf, rpc_buf, RPC_MIN_LENGTH,
			RPC_MAX_LENGTH);
	if (!len)
		return 0;

	/* fragment header (length 4b) skipped in tcp */
	uint32_t *rpc_data = (uint32_t *)rpc_buf;
	if (npf_cache_ipproto(npc) == IPPROTO_TCP)
		++rpc_data;

	xid = *rpc_data++;
	type = ntohl(*rpc_data++);

	switch (type) {
	case CALL:
		rc = rpc_manage_request(se, xid, rpc_data, rpc_buf, len);
		break;
	case REPLY:
		rc = rpc_manage_reply(se, xid, rpc_data, port, rpc_buf, len);
		break;
	default:
		return -EINVAL;
	}
	return rc;

}

/* Parse a portmap packet for tuple insertion */
static int rpc_handle_packet(npf_cache_t *npc, npf_session_t *se,
			     struct rte_mbuf *nbuf, const npf_addr_t *srcip,
			     const npf_addr_t *dstip, struct npf_alg *rpc)
{
	int rc;
	uint16_t port = 0;

	rc = rpc_parse_packet(npc, se, nbuf, &port);
	if (rc)
		return rc;

	if (port > 0)
		rc = rpc_tuple_insert(rpc, npc, se, srcip, dstip, port);
	return rc;
}

/*
 * ALG inspect for non-NATd pkts
 */
void rpc_alg_inspect(struct npf_session *se, struct npf_cache *npc,
		     struct rte_mbuf *nbuf, struct npf_alg *alg)
{
	rpc_handle_packet(npc, se, nbuf, npf_cache_dstip(npc),
			  npf_cache_srcip(npc), alg);
}

/* ALG session initialization */
int rpc_alg_session_init(struct npf_session *se, struct apt_tuple *nt)
{
	npf_session_t *parent;
	uint32_t alg_flags;
	int rc = 0;

	npf_alg_session_set_inspect(se, true);

	switch (apt_tuple_get_table_type(nt)) {
	case APT_MATCH_DPORT:
		/* Parent flow */
		npf_alg_session_set_flag(se, RPC_ALG_CNTL);
		break;

	case APT_MATCH_ANY_SPORT:
		/* Child flow */
		parent = apt_tuple_get_active_session(nt);
		if (!parent) {
			rc = -ENOENT;
			break;
		}

		/* Transfer alg_flags from tuple to child session */
		alg_flags = apt_tuple_get_client_flags(nt);
		npf_alg_session_set_flag(se, alg_flags | RPC_ALG_DATA);

		/* Link parent and child sessions */
		npf_session_link_child(parent, se);
		break;

	default:
		rc = -EINVAL;
		break;
	}

	return rc;
}

/* ALG session destroy */
void rpc_alg_session_destroy(struct npf_session *se)
{
	struct npf_session_alg *sa;

	sa = npf_session_get_alg_ptr(se);
	if (sa) {
		struct rpc_request *rr;

		/* Invalidate the stored request data */
		rr = &sa->sa_rpc.sar_request;
		rr->rr_xid = 0;
	}
}

/*
 * ALG inspect for NATd packets.
 */
int rpc_alg_nat(struct npf_session *se, struct npf_cache *npc,
		struct rte_mbuf *nbuf, struct npf_nat *nt,
		struct npf_alg *alg, int dir)
{
	npf_addr_t addr;
	in_port_t port __unused;
	int rc;

	/* Get orig addr from the NAT data */
	npf_nat_get_orig(nt, &addr, &port);

	if (dir == PFIL_OUT)
		rc = rpc_handle_packet(npc, se, nbuf,
				       npf_cache_dstip(npc), &addr, alg);
	else
		rc = rpc_handle_packet(npc, se, nbuf,
				       &addr, npf_cache_srcip(npc), alg);

	return rc;
}

/*
 * ALG protocol and port configuration
 */
int rpc_alg_config(struct npf_alg *rpc, enum alg_config_op op, int argc,
		   char *const argv[])
{
	int i;
	int rc = 0;
	struct npf_alg_config_item ci;

	for (i = 0; i < argc; i++) {
		ci.ci_datum = strtoul(argv[i], NULL, 10);
		if (ci.ci_datum)
			rc = npf_alg_manage_config_item(rpc,
					&rpc->na_configs[RPC_PROG_CONFIG],
					op, &ci);
	}

	return rc;
}

/*
 * Notification ALG is being reset
 */
int rpc_alg_reset(struct npf_alg *rpc)
{
	rpc_destroy_list(rpc);
	return 0;
}

/* Default port config */
static const struct npf_alg_config_item rpc_ports[] = {
	{ IPPROTO_UDP, (NPF_TUPLE_KEEP | NPF_TUPLE_MATCH_PROTO_PORT),
		0, PMAPPORT },
	{ IPPROTO_TCP, (NPF_TUPLE_KEEP | NPF_TUPLE_MATCH_PROTO_PORT),
		0, PMAPPORT },
};

/* Default programs config */
static const struct npf_alg_config_item rpc_programs[] = {
	{ 0, 0, 0, 100000 },	/* portmapper */
	{ 0, 0, 0, 100003 },	/* nfs */
	{ 0, 0, 0, 100005 },	/* mountd */
	{ 0, 0, 0, 100021 },	/* nlockmgr */
	{ 0, 0, 0, 100227 }	/* nfs_acl */
};

struct npf_alg *npf_alg_rpc_create_instance(struct npf_alg_instance *ai)
{
	struct npf_alg *rpc;
	struct rpc_private *rp = NULL;
	int rc = -ENOMEM;

	rpc = npf_alg_create_alg(ai, NPF_ALG_ID_RPC);
	if (!rpc)
		goto bad;

	/* setup default configs, one for ports, and one for programs */
	rpc->na_num_configs = 2;

	rpc->na_configs[RPC_PORT_CONFIG].ac_items = rpc_ports;
	rpc->na_configs[RPC_PORT_CONFIG].ac_item_cnt = ARRAY_SIZE(rpc_ports);
	rpc->na_configs[RPC_PORT_CONFIG].ac_handler = npf_alg_port_handler;

	rpc->na_configs[RPC_PROG_CONFIG].ac_items = rpc_programs;
	rpc->na_configs[RPC_PROG_CONFIG].ac_item_cnt = ARRAY_SIZE(rpc_programs);
	rpc->na_configs[RPC_PROG_CONFIG].ac_handler = rpc_alg_program_handler;

	/* Allocate program list */
	rp = malloc_aligned(sizeof(struct rpc_private));
	if (!rp)
		goto bad;

	rpc->na_private = rp;
	CDS_INIT_LIST_HEAD(&rp->rpc_lh);

	/* Now register */
	rc = npf_alg_register(rpc);
	if (rc)
		goto bad;

	/* Take reference on an alg application instance */
	npf_alg_get(rpc);

	return rpc;

bad:
	if (net_ratelimit())
		RTE_LOG(ERR, FIREWALL, "ALG: RPC instance failed: %d\n", rc);
	free(rp);
	free(rpc);
	return NULL;
}

void npf_alg_rpc_destroy_instance(struct npf_alg *rpc)
{
	if (!rpc)
		return;

	/* Expire or delete tuples */
	alg_apt_instance_client_destroy(rpc->na_ai->ai_apt, rpc);

	rpc_destroy_list(rpc);
	free(rpc->na_private);

	rpc->na_private = NULL;
	rpc->na_enabled = false;
	rpc->na_ai = NULL;

	/* Release reference on an alg application instance */
	npf_alg_put(rpc);
}
