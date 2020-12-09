/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2013-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * NPF ALG for TFTP
 *
 * A TFTP ALG based on RFCs 1350 and 2347-2349.
 */

#include <errno.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <rte_log.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "compiler.h"
#include "npf/npf.h"
#include "npf/alg/alg.h"
#include "npf/npf_cache.h"
#include "npf/npf_nat.h"
#include "npf/npf_session.h"
#include "util.h"
#include "vplane_log.h"

struct ifnet;
struct rte_mbuf;

/* For verifying tftp packets.. */
#define TFTP_OPCODE_SIZE 2

/* Default port */
#define TFTP_DEFAULT_PORT	69

/* ALG's specific flags*/
#define TFTP_ALG_CNTL	0x040000  /* tftp control flow. means WRQ or RRQ */
#define TFTP_ALG_SNAT	0x000010
#define TFTP_ALG_DNAT	0x000020

/* tftp_alg_config() - Config routine for tftp */
static int tftp_alg_config(struct npf_alg *tftp, int op, int argc,
			char * const argv[])
{
	int rc = 0;
	int i;
	struct npf_alg_config_item ci = {
		.ci_proto = IPPROTO_UDP,
		.ci_flags = (NPF_TUPLE_KEEP | NPF_TUPLE_MATCH_PROTO_PORT)
	};

	if (strcmp(argv[0], "port") != 0)
		return -EINVAL;
	argc--; argv++;

	for (i = 0; i < argc; i++) {
		ci.ci_datum = npf_port_from_str(argv[i]);
		if (!ci.ci_datum)
			continue;
		rc = npf_alg_manage_config_item(tftp, &tftp->na_configs[0],
				op, &ci);
		if (rc)
			return rc;
	}
	return rc;
}

/* Create and insert a tuple for an expected flow */
static int tftp_alg_tuple_insert(struct npf_alg *tftp,
				npf_cache_t *npc, npf_session_t *se,
				const npf_addr_t *saddr, in_port_t sport,
				const npf_addr_t *daddr, in_port_t dport,
				uint32_t alg_flags)
{
	struct apt_match_key m = { 0 };
	struct apt_tuple *at;

	m.m_proto = IPPROTO_UDP;
	m.m_ifx = npf_session_get_if_index(se);
	m.m_alen = npc->npc_alen;
	m.m_dport = dport;
	m.m_sport = sport;
	m.m_dstip = daddr;
	m.m_srcip = saddr;
	m.m_match = APT_MATCH_ANY_SPORT;

	at = apt_tuple_create_and_insert(tftp->na_ai->ai_apt, &m,
					 npf_alg_get(tftp),
					 alg_flags, NPF_ALG_TFTP_NAME,
					 true, false);

	if (!at) {
		npf_alg_put(tftp);
		RTE_LOG(ERR, FIREWALL, "TFTP: tuple insert\n");
		return -EINVAL;
	}
	apt_tuple_set_session(at, se);

	return 0;
}

/*
 * tftp_parse_and_decide() - Parse a tftp opcode and return a decision to
 * insert a tuple.
 */
static int tftp_parse_and_decide(npf_cache_t *npc, struct rte_mbuf *nbuf,
		bool *do_insert)
{
	char buf[TFTP_OPCODE_SIZE];
	uint16_t len;

	/*
	 * All tftp packets must have an opcode as the first
	 * two bytes of the packet.  So verify
	 */
	len = npf_payload_fetch(npc, nbuf, buf,
			TFTP_OPCODE_SIZE, TFTP_OPCODE_SIZE);
	if (!len)
		return -EINVAL;  /* always UDP */

	/* op codes are ascii and not strings */
	if (*buf)
		return -EINVAL;

	/* Only insert a tuple for read/write reqs. */
	switch (buf[1]) {
	case 1:
	case 2:
		*do_insert = true;
		return 0;
	case 3:
	case 4:
	case 5:
	case 6:
		return 0;
	default:
		return -EINVAL;
	}

	return 0;
}

/* tftp_alg_natout() - Packet NAT out*/
static int tftp_alg_nat_out(npf_session_t *se, npf_cache_t *npc,
			struct rte_mbuf *nbuf __unused, npf_nat_t *nat)
{
	npf_addr_t taddr;
	struct npf_alg *tftp = npf_alg_session_get_alg(se);
	in_port_t tport;
	bool insert = false;
	int rc;

	rc = tftp_parse_and_decide(npc, nbuf, &insert);
	if (insert) {
		npf_nat_get_trans(nat, &taddr, &tport);
		rc = tftp_alg_tuple_insert(tftp, npc, se, npf_cache_dstip(npc),
				0, &taddr, tport, TFTP_ALG_SNAT);
		/* Turn off inspection, we are natting */
		npf_alg_session_set_inspect(se, false);
	}
	return rc;
}

/* tftp_alg_nat_in() - Packet NAT in */
static int tftp_alg_nat_in(npf_session_t *se, npf_cache_t *npc,
			struct rte_mbuf *nbuf __unused, npf_nat_t *nat)
{
	npf_addr_t addr;
	struct npf_alg *tftp = npf_alg_session_get_alg(se);
	in_port_t port;
	struct udphdr *uh = &npc->npc_l4.udp;
	bool insert = false;
	int rc;

	rc = tftp_parse_and_decide(npc, nbuf, &insert);
	if (insert) {
		npf_nat_get_trans(nat, &addr, &port);
		rc = tftp_alg_tuple_insert(tftp, npc, se, &addr, 0,
			npf_cache_srcip(npc), uh->source, TFTP_ALG_DNAT);
		/* Turn off inspection, we are natting */
		npf_alg_session_set_inspect(se, false);
	}
	return rc;
}

/*
 * Create a reverse nat for tftp. Can only be done on
 * first data packet - we need the server src port
 */
static int tftp_create_nat(npf_session_t *se, npf_nat_t *pnat, npf_cache_t *npc,
			   const int di, struct apt_tuple *nt)
{
	struct npf_ports *p;
	npf_addr_t taddr;
	npf_addr_t oaddr;
	in_port_t oport;
	in_port_t tport;
	struct npf_alg_nat *an;
	uint32_t alg_flags;
	int rc;

	alg_flags = apt_tuple_get_client_flags(nt);

	/* Ignore stateful sessions */
	if (!(alg_flags & (TFTP_ALG_SNAT | TFTP_ALG_DNAT)))
		return 0;

	an = zmalloc_aligned(sizeof(struct npf_alg_nat));
	if (!an)
		return -ENOMEM;

	p = &npc->npc_l4.ports;

	npf_nat_get_trans(pnat, &taddr, &tport);
	npf_nat_get_orig(pnat, &oaddr, &oport);

	an->an_flags = NPF_NAT_REVERSE;
	an->an_taddr = taddr;
	an->an_oaddr = oaddr;
	an->an_vrfid = npf_session_get_vrfid(se);

	if (alg_flags & TFTP_ALG_DNAT) {
		/* Only translate the address, port comes from server */
		an->an_tport = an->an_oport = p->s_port;
	} else if (alg_flags & TFTP_ALG_SNAT) {
		/* Translate both addr and port */
		an->an_tport = tport;
		an->an_oport = oport;
	}

	/* Consumes 'an' if successful. */
	rc = npf_alg_session_nat(se, pnat, npc, di, NULL, an);

	if (rc < 0)
		free(an);

	return rc;
}

/* Nat inspect */
static void tftp_alg_nat_inspect(npf_session_t *se, npf_cache_t *npc __unused,
				npf_nat_t *nt, int di __unused)
{
	/* Only for the control flow */
	if (npf_alg_session_test_flag(se, TFTP_ALG_CNTL))
		npf_nat_setalg(nt, npf_alg_session_get_alg(se));
}

/* ALG inspect routine */
static void tftp_alg_inspect(npf_session_t *se, npf_cache_t *npc,
		struct rte_mbuf *nbuf, struct ifnet *ifp __unused,
		int di __unused)
{
	struct npf_alg *tftp = npf_alg_session_get_alg(se);
	struct udphdr *uh = &npc->npc_l4.udp;
	bool insert = false;

	if (npf_iscached(npc, NPC_NATTED))
		return;

	tftp_parse_and_decide(npc, nbuf, &insert);
	if (insert) {
		tftp_alg_tuple_insert(tftp, npc, se, npf_cache_dstip(npc), 0,
			npf_cache_srcip(npc), uh->source, 0);
		/*
		 * We cannot turn off inspection here since it is
		 * possible this session handle could be re-used
		 */
	}
}

/*
 * Session init
 */
static int tftp_alg_session_init(npf_session_t *se, npf_cache_t *npc,
				 struct apt_tuple *nt, const int di)
{
	npf_session_t *parent;
	int rc = 0;

	npf_alg_session_set_inspect(se, true);

	switch (apt_tuple_get_table_type(nt)) {
	case APT_MATCH_DPORT:
		/* Parent flow */
		npf_alg_session_set_flag(se, TFTP_ALG_CNTL);
		break;

	case APT_MATCH_ANY_SPORT:
		/* Child flow */
		parent = apt_tuple_get_active_session(nt);
		if (!parent) {
			rc = -ENOENT;
			break;
		}

		rc = tftp_create_nat(se, npf_alg_parent_nat(parent),
				     npc, di, nt);
		if (!rc)
			npf_session_link_child(parent, se);
		break;

	default:
		rc = -EINVAL;
		break;
	}

	return rc;
}

/* alg struct */
static const struct npf_alg_ops tftp_ops = {
	.name		= NPF_ALG_TFTP_NAME,
	.se_init	= tftp_alg_session_init,
	.config		= tftp_alg_config,
	.inspect	= tftp_alg_inspect,
	.nat_inspect	= tftp_alg_nat_inspect,
	.nat_in		= tftp_alg_nat_in,
	.nat_out	= tftp_alg_nat_out,
};

/* Default port config */
static const struct npf_alg_config_item tftp_ports[] = {
	{ IPPROTO_UDP, (NPF_TUPLE_KEEP | NPF_TUPLE_MATCH_PROTO_PORT),
		0, TFTP_DEFAULT_PORT }
};

/* Create instance */
struct npf_alg *npf_alg_tftp_create_instance(struct npf_alg_instance *ai)
{
	struct npf_alg *tftp;
	int rc = -ENOMEM;

	tftp = npf_alg_create_alg(ai, NPF_ALG_ID_TFTP);
	if (!tftp)
		goto bad;

	tftp->na_ops = &tftp_ops;

	tftp->na_num_configs = 1;
	tftp->na_configs[0].ac_items = tftp_ports;
	tftp->na_configs[0].ac_item_cnt = ARRAY_SIZE(tftp_ports);
	tftp->na_configs[0].ac_handler = npf_alg_port_handler;

	rc = npf_alg_register(tftp);
	if (rc)
		goto bad;

	/* Take reference on an alg application instance */
	npf_alg_get(tftp);

	return tftp;

bad:
	if (net_ratelimit())
		RTE_LOG(ERR, FIREWALL, "ALG: TFTP instance failed: %d\n", rc);
	free(tftp);
	return NULL;
}

void npf_alg_tftp_destroy_instance(struct npf_alg *tftp)
{
	if (!tftp)
		return;

	/* Expire or delete tuples */
	alg_apt_instance_client_destroy(tftp->na_ai->ai_apt, tftp);

	tftp->na_enabled = false;
	tftp->na_ai = NULL;

	/* Release reference on an alg application instance */
	npf_alg_put(tftp);
}
