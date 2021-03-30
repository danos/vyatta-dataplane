/*
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2013-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * NPF ALG for FTP
 *
 * FTP ALG manages the payload of specific control messages and creates tuples
 * for the expected flows. If there is NAT configured, ALG does the payload
 * translation according to control flow's NAT structure. Also ALG manages to
 * create a policy for the data flow from the server.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <rte_branch_prediction.h>
#include <rte_log.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "compiler.h"
#include "npf/npf.h"
#include "npf/alg/alg.h"
#include "npf/alg/alg_session.h"
#include "npf/npf_cache.h"
#include "npf/npf_nat.h"
#include "npf/npf_session.h"
#include "util.h"
#include "vplane_log.h"
#include "npf/alg/alg_ftp.h"

struct ifnet;
struct rte_mbuf;

/* FTP Control msg/response data */
struct ftp_parse {
	uint16_t	fcp_port;
	int		fcp_family;
	uint32_t	fcp_flags;
	struct in6_addr	fcp_addr;
	bool		fcp_parens;
	char		fcp_msg[50];
	uint		fcp_msg_len;
};

/* Min and Max payload lengths we can parse */
#define FTP_MIN_PAYLOAD 11
#define FTP_MAX_PAYLOAD 255

/* default ports */
#define FTP_DEFAULT_PORT 21
#define FTP_DATA_PORT 20

/*
 * tuple timeout.
 *
 * Since the data flow doesn't start w/o human
 * action, set a relatively very large timeout.
 * (seconds)
 */
#define FTP_TUPLE_TIMEOUT 120

/* ALG specific flags */
#define FTP_ALG_CNTL	0x10000000  /* Ftp control flow. */
#define FTP_ALG_DATA	0x20000000  /* Ftp data flow. */
#define FTP_ALG_EPRT	0x00000001  /* pkt contains EPRT cmd  */
#define FTP_ALG_PORT	0x00000002  /* pkt contains PORT cmd  */
#define FTP_ALG_227	0x00000004  /* pkt contains 227 rsp */
#define FTP_ALG_229	0x00000008  /* pkt contains 229 rsp */
#define FTP_ALG_PASSIVE	0x00000010  /* Passive connection */
#define FTP_ALG_ACTIVE	0x00000020  /* Active connection */

#define FTP_ALG_MASK  (FTP_ALG_EPRT | FTP_ALG_PORT | FTP_ALG_227 | FTP_ALG_229)

#define ftp_passive(fp) ((fp)->fcp_flags & FTP_ALG_PASSIVE)
#define ftp_active(fp)  ((fp)->fcp_flags & FTP_ALG_ACTIVE)
#define ftp_cmd(fp)     ((fp)->fcp_flags & FTP_ALG_MASK)

/* parse a PORT control msg */
static int ftp_parse_port(struct ftp_parse *fp, char *sptr, int dlen)
{
	int rc;
	uint8_t b[2];

	/* Format: "PORT A,D,D,R,PO,RT". */

	/* Return if data length is too short. */
	if (dlen < 18)
		return -ENOENT;

	if (memcmp("PORT ", sptr, 5) != 0)
		return -ENOENT;

	/* scan rest, make sure we stop */
	rc = sscanf(&sptr[5], "%3hhu,%3hhu,%3hhu,%3hhu,%3hhu,%3hhu",
			&fp->fcp_addr.s6_addr[0],
			&fp->fcp_addr.s6_addr[1],
			&fp->fcp_addr.s6_addr[2],
			&fp->fcp_addr.s6_addr[3],
			&b[0],
			&b[1]);
	if (rc != 6)
		return -EINVAL;

	fp->fcp_port = htons((b[0] << 8) + b[1]);
	fp->fcp_family = AF_INET;
	fp->fcp_flags = (FTP_ALG_DATA | FTP_ALG_ACTIVE | FTP_ALG_PORT);
	return 0;
}

/* parse a 229 response */
static int ftp_parse_229(struct ftp_parse *fp, npf_cache_t *npc,
			char *sptr, int dlen)
{
	int rc;
	const char *s;
	char c;

	/* Format: "229 Entering Extended Passive Mode (|||PORT|)" */

	/* Return if data length is too short. */
	if (dlen < 11)
		return -ENOENT;

	if (strncmp("229 ", sptr, 4) != 0)
		return -ENOENT;

	/* advance to '(' */
	s = strchr((sptr + 4), '(');

	if (!s)		/* does not have a '(' */
		return -EINVAL;

	/* verify by parsing */
	rc = sscanf(s, "(%c%c%c%5hu%c)", &c, &c, &c, &fp->fcp_port, &c);
	if (rc != 5)
		return -EINVAL;
	fp->fcp_flags = (FTP_ALG_DATA | FTP_ALG_PASSIVE | FTP_ALG_229);
	fp->fcp_port = htons(fp->fcp_port);

	fp->fcp_family = AF_INET;
	if (unlikely(npc->npc_alen > 4))
		fp->fcp_family = AF_INET6;

	return 0;
}

/* parse a EPRT control msg */
static int ftp_parse_eprt(struct ftp_parse *fp, char *sptr, int dlen)
{
	int rc;
	unsigned long port;
	char addr[FTP_MAX_PAYLOAD+1];
	char c;
	int fam;

	/* Format: "EPRT |1|A.D.D.R|PORT|". */

	/* Return if data length is invalid */
	if (dlen < 18)
		return -ENOENT;

	if (memcmp("EPRT ", sptr, 5) != 0)
		return -ENOENT;

	rc = sscanf(sptr+5, "%c%d%c%64[0-9.a-fA-f:]%c%lu",
			&c, &fam, &c, addr, &c, &port);
	if (rc != 6)
		return -EINVAL;

	switch (fam) {
	case 1:
		fp->fcp_family = AF_INET;
		break;
	case 2:
		fp->fcp_family = AF_INET6;
		break;
	default:
		return -EINVAL; /* Invalid */
	}

	rc = inet_pton(fp->fcp_family, addr, (void *) &fp->fcp_addr);
	if (rc != 1)
		return -EINVAL; /* Invalid */

	/* Port */
	if (!port || port > USHRT_MAX)
		return -EINVAL;
	fp->fcp_port = htons(port);
	fp->fcp_flags = (FTP_ALG_ACTIVE | FTP_ALG_DATA | FTP_ALG_EPRT);

	return 0;
}

/* parse a 227 response */
static int ftp_parse_227(struct ftp_parse *fp, char *sptr, int dlen)
{
	int rc;
	uint i;
	uint8_t b[2];
	const char *s;

	/*
	 * Format: Message starts with "227 ", and has "A,D,D,R,PO,RT" in the
	 * msg.
	 *
	 * Typically it will be "227 Entering Passive Mode (A,D,D,R,PO,RT)",
	 * but we allow anything between the "227" and the first digit of the
	 * host.
	 */

	/* Return if data length is too short. */
	if (dlen < 17)
		return -ENOENT;

	if (strncmp("227 ", sptr, 4) != 0)
		return -ENOENT;

	/*
	 * Starting after "227 ", look for the first digit (0x30-0x39)
	 */
	for (i = 4, s = sptr + 4; i < sizeof(fp->fcp_msg) && *s != 0x0d;
	     i++, s++) {

		if (*s >= 0x30 && *s <= 0x39)
			break;
	}

	if (*s < 0x30 || *s > 0x39)
		return -ENOENT;

	/* Are parenthesis around the host and port? */
	if (*(s-1) == '(')
		fp->fcp_parens = true;

	rc = sscanf(s, "%3hhu,%3hhu,%3hhu,%3hhu,%3hhu,%3hhu",
		    &fp->fcp_addr.s6_addr[0],
		    &fp->fcp_addr.s6_addr[1],
		    &fp->fcp_addr.s6_addr[2],
		    &fp->fcp_addr.s6_addr[3],
		    &b[0],
		    &b[1]);

	if (rc != 6)
		return -EINVAL;

	fp->fcp_port = htons((b[0] << 8) + b[1]);
	fp->fcp_family = AF_INET;
	fp->fcp_flags = (FTP_ALG_DATA | FTP_ALG_PASSIVE | FTP_ALG_227);

	/*
	 * Remember the initial part of the message, up to the first digit
	 * (but not including the parenthesis, if there is one)
	 */
	if (fp->fcp_parens)
		fp->fcp_msg_len = (uint)(s - sptr - 1);
	else
		fp->fcp_msg_len = (uint)(s - sptr);

	if (fp->fcp_msg_len > sizeof(fp->fcp_msg))
		return -EINVAL;

	memcpy(fp->fcp_msg, sptr, fp->fcp_msg_len);

	return 0;
}

/* ftp_parse_payload() - See if this payload has anything interesting.*/
static int ftp_parse_payload(npf_cache_t *npc, struct rte_mbuf *nbuf,
				struct ftp_parse *fp, char *payload, int *plen)
{
	uint16_t dlen;
	int rc;

	/* Fetch the payload so we can parse it freely */
	dlen = npf_payload_fetch(npc, nbuf, payload, FTP_MIN_PAYLOAD,
			FTP_MAX_PAYLOAD);
	if (dlen == 0)
		return -ENOENT;
	payload[dlen] = '\0';

	*plen = dlen;

	/*
	 * Parse for cmd/responses.
	 * most common first
	 */
	rc = ftp_parse_eprt(fp, payload, dlen);
	if (!rc)
		return rc;
	rc = ftp_parse_227(fp, payload, dlen);
	if (!rc)
		return rc;
	rc = ftp_parse_229(fp, npc, payload, dlen);
	if (!rc)
		return rc;
	rc = ftp_parse_port(fp, payload, dlen);

	return rc;
}

/* ftp_nat_port() - Nat the PORT command */
static int ftp_nat_port(const struct ftp_parse *fp, char *payload)
{
	in_port_t port = ntohs(fp->fcp_port);

	return sprintf(payload, "PORT %u,%u,%u,%u,%d,%d\r\n",
			fp->fcp_addr.s6_addr[0],
			fp->fcp_addr.s6_addr[1],
			fp->fcp_addr.s6_addr[2],
			fp->fcp_addr.s6_addr[3],
			(port >> 8),
			(port & 0xFF));
}

/* ftp_nat_227() - Nat the 227 response */
static int ftp_nat_227(const struct ftp_parse *fp, char *payload)
{
	in_port_t port = ntohs(fp->fcp_port);
	int l;

	/* 227 messages always use the saved message portion */
	if (fp->fcp_msg_len == 0)
		return 0;

	memcpy(payload, fp->fcp_msg, fp->fcp_msg_len);
	l = fp->fcp_msg_len;

	l += snprintf(payload + l, FTP_MAX_PAYLOAD - l,
		      "%s%u,%u,%u,%u,%d,%d%s\r\n",
		      fp->fcp_parens ? "(" : "",
		      fp->fcp_addr.s6_addr[0],
		      fp->fcp_addr.s6_addr[1],
		      fp->fcp_addr.s6_addr[2],
		      fp->fcp_addr.s6_addr[3],
		      (port >> 8), (port & 0xFF),
		      fp->fcp_parens ? ")." : "");

	return l;
}

/* ftp_nat_229() - Nat the 229 response */
static int ftp_nat_229(const struct ftp_parse *fp, char *payload)
{
	return sprintf(payload,
			"229 Entering Extended Passive Mode (|||%hu|).\r\n",
			ntohs(fp->fcp_port));
}

/* ftp_nat_eprt() - Nat the EPRT command */
static int ftp_nat_eprt(const struct ftp_parse *fp, char *payload)
{
	char buf[INET6_ADDRSTRLEN];

	if (!inet_ntop(fp->fcp_family, &fp->fcp_addr, buf, sizeof(buf)))
		return -EINVAL; /* wtf? */

	return sprintf(payload, "EPRT |%u|%s|%u|\r\n",
			(fp->fcp_family == AF_INET) ? 1 : 2,
			buf,
			ntohs(fp->fcp_port));
}

/*
 * ALG protocol and port configuration
 */
int ftp_alg_config(struct npf_alg *ftp, enum alg_config_op op, int argc,
		   char *const argv[])
{
	int rc;
	int i;
	struct npf_alg_config_item ci = {
		.ci_proto = IPPROTO_TCP,
		.ci_flags = (NPF_TUPLE_KEEP | NPF_TUPLE_MATCH_PROTO_PORT),
		.ci_alg_flags = 0
	};

	/* Only ports */
	if (strcmp(argv[0], "port") != 0)
		return -EINVAL;
	argc--; argv++;

	for (i = 0; i < argc; i++) {
		/* Must be in host order */
		ci.ci_datum = npf_port_from_str(argv[i]);
		if (!ci.ci_datum)
			continue;
		rc = npf_alg_manage_config_item(ftp, &ftp->na_configs[0],
				op, &ci);
		if (rc)
			return rc;
	}

	return 0;
}

static int ftp_alg_translate_payload(npf_session_t *se,
		const struct ftp_parse *fp, npf_cache_t *npc,
		struct rte_mbuf *nbuf, char *payload, const int di)
{
	int nplen = 0;

	switch (ftp_cmd(fp)) {
	case FTP_ALG_EPRT:
		nplen = ftp_nat_eprt(fp, payload);
		break;
	case FTP_ALG_PORT:
		nplen = ftp_nat_port(fp, payload);
		break;
	case FTP_ALG_227:
		nplen = ftp_nat_227(fp, payload);
		break;
	case FTP_ALG_229:
		nplen = ftp_nat_229(fp, payload);
		break;
	default:
		return -1;
	}

	if (nplen <= 0)
		return -ENOTSUP;

	return npf_payload_update(se, npc, nbuf, payload, di, nplen);
}

static int ftp_alg_tuple_insert(struct npf_alg *ftp,
				npf_cache_t *npc, npf_session_t *se,
				const npf_addr_t *saddr, in_port_t sport,
				const npf_addr_t *daddr, in_port_t dport,
				uint32_t alg_flags, struct npf_alg_nat *an)
{
	struct apt_match_key m = { 0 };
	struct apt_tuple *at;

	m.m_proto = IPPROTO_TCP;
	m.m_ifx = npf_session_get_if_index(se);
	m.m_alen = npc->npc_alen;
	m.m_dport = dport;
	m.m_sport = sport;
	m.m_dstip = daddr;
	m.m_srcip = saddr;

	if (sport)
		m.m_match = APT_MATCH_ALL;
	else
		m.m_match = APT_MATCH_ANY_SPORT;

	/* Tuple takes a reference on the alg */
	at = apt_tuple_create_and_insert(ftp->na_ai->ai_apt, &m,
					 npf_alg_get(ftp),
					 alg_flags,
					 NPF_ALG_FTP_NAME,
					 true, false);

	if (!at) {
		RTE_LOG(ERR, FIREWALL, "FTP: tuple insert\n");
		npf_alg_put(ftp);
		return -EINVAL;
	}
	apt_tuple_set_session(at, se);
	apt_tuple_set_nat(at, an);
	apt_tuple_set_timeout(at, FTP_TUPLE_TIMEOUT);

	return 0;
}

static int ftp_alg_snat_passive(npf_session_t *parent, npf_cache_t *npc,
		npf_nat_t *pnat, struct ftp_parse *fp)
{
	struct npf_alg *ftp = npf_alg_session_get_alg(parent);
	npf_addr_t oaddr;
	in_port_t tmp;

	npf_nat_get_orig(pnat, &oaddr, &tmp);
	return ftp_alg_tuple_insert(ftp, npc, parent, &oaddr, 0,
			npf_cache_srcip(npc), fp->fcp_port, fp->fcp_flags,
			NULL);
}

static int ftp_alg_dnat_passive(npf_session_t *parent, npf_cache_t *npc,
		struct rte_mbuf *nbuf, char *payload, npf_nat_t *pnat,
		struct ftp_parse *fp)
{
	struct npf_alg *ftp = npf_alg_session_get_alg(parent);
	npf_addr_t oaddr;
	in_port_t tmp;
	int rc;

	npf_nat_get_orig(pnat, &oaddr, &tmp);

	/* a 227 response contains the server addr, translate */
	if (fp->fcp_flags & FTP_ALG_227) {
		fp->fcp_addr = oaddr;
		rc = ftp_alg_translate_payload(parent, fp, npc, nbuf,
				payload, PFIL_OUT);
		if (rc)
			return rc;
	}

	return ftp_alg_tuple_insert(ftp, npc, parent, npf_cache_dstip(npc),
			0, &oaddr, fp->fcp_port,
			fp->fcp_flags, NULL);
}

static int ftp_alg_snat_active(npf_session_t *parent, npf_cache_t *npc,
		struct rte_mbuf *nbuf, struct ftp_parse *fp,
		char *payload)
{
	struct npf_alg *ftp = npf_alg_session_get_alg(parent);
	in_port_t port;
	struct npf_alg_nat *an = NULL;
	npf_addr_t addr;
	int rc;

	/* Reserve a translation */
	port = fp->fcp_port;
	addr = fp->fcp_addr;
	rc = npf_alg_reserve_translations(parent, 1, false, npc->npc_alen,
			&addr, &port);
	if (rc)
		return rc;

	an = zmalloc_aligned(sizeof(struct npf_alg_nat));
	if (!an)
		goto bad;

	an->an_flags = NPF_NAT_REVERSE | NPF_NAT_CLONE_APM | NPF_NAT_MAP_PORT;
	an->an_taddr = addr;
	an->an_tport = port;
	an->an_oaddr = fp->fcp_addr;
	an->an_oport = fp->fcp_port;
	an->an_vrfid = npf_session_get_vrfid(parent);

	/* Update payload with translation */
	fp->fcp_port = port;
	fp->fcp_addr = addr;
	rc = ftp_alg_translate_payload(parent, fp, npc, nbuf,
			payload, PFIL_OUT);
	if (rc)
		goto bad;

	/* Set the tuple */
	rc = ftp_alg_tuple_insert(ftp, npc, parent, npf_cache_dstip(npc),
			htons(FTP_DATA_PORT), &addr, port,
			fp->fcp_flags, an);
	if (!rc)
		return rc;

bad:
	npf_alg_free_translation(parent, &addr, port);
	free(an);
	return rc;

}

static int ftp_alg_dnat_active(npf_session_t *parent,
		npf_cache_t *npc, npf_nat_t *ns, struct ftp_parse *fp)
{
	in_port_t tmp;
	struct npf_alg *ftp = npf_alg_session_get_alg(parent);
	struct npf_alg_nat *an;
	int rc;

	an = zmalloc_aligned(sizeof(struct npf_alg_nat));
	if (!an)
		return -ENOMEM;

	/*
	 * All we need is the addr translation, ftp expects a certain
	 * src port
	 */
	an->an_flags = NPF_NAT_REVERSE;
	npf_nat_get_trans(ns, &an->an_taddr, &tmp);
	npf_nat_get_orig(ns, &an->an_oaddr, &tmp);
	an->an_tport = an->an_oport = htons(FTP_DATA_PORT);
	an->an_vrfid = npf_session_get_vrfid(parent);

	rc =  ftp_alg_tuple_insert(ftp, npc, parent, &an->an_taddr,
			an->an_oport, &fp->fcp_addr,
			fp->fcp_port, fp->fcp_flags, an);
	if (rc)
		free(an);
	return rc;
}

/*
 * ALG inspect for NATd packets.
 */
int ftp_alg_nat(struct npf_session *se, struct npf_cache *npc,
		struct rte_mbuf *nbuf, struct npf_nat *ns, int di)
{
	struct ftp_parse fp = { 0 };
	char payload[FTP_MAX_PAYLOAD+1];
	bool forw;
	int rc, plen, type;

	rc = ftp_parse_payload(npc, nbuf, &fp, payload, &plen);
	if (rc) {
		if (rc == -ENOENT) /* Not interested */
			return 0;
		return rc;
	}

	(void)npf_session_retnat(se, di, &forw);

	type = npf_nat_type(ns);

	if (ftp_active(&fp) && (type == NPF_NATOUT))
		rc = ftp_alg_snat_active(se, npc,  nbuf, &fp, payload);
	else if (ftp_active(&fp) && (type == NPF_NATIN))
		rc = ftp_alg_dnat_active(se, npc, ns, &fp);
	else if (ftp_passive(&fp) && (type == NPF_NATIN))
		rc = ftp_alg_dnat_passive(se, npc, nbuf, payload, ns, &fp);
	else if (ftp_passive(&fp) && (type == NPF_NATOUT))
		rc = ftp_alg_snat_passive(se, npc, ns, &fp);
	else
		rc = -EINVAL;

	return rc;
}

/*
 * ALG inspect for non-NATd pkts
 */
void ftp_alg_inspect(npf_session_t *parent, npf_cache_t *npc,
		     struct rte_mbuf *nbuf, struct npf_alg *ftp)
{
	struct ftp_parse fp = { 0 };
	char payload[FTP_MAX_PAYLOAD+1];
	const npf_addr_t *dstip;
	const npf_addr_t *srcip;
	in_port_t sport;
	in_port_t dport;
	int rc;
	int plen;

	rc = ftp_parse_payload(npc, nbuf, &fp, payload, &plen);
	if (rc)
		return;

	srcip = npf_cache_dstip(npc);
	dport = fp.fcp_port;

	/* Now set the tuple. */
	if (ftp_passive(&fp)) {
		sport = 0;
		dstip = npf_cache_srcip(npc);
	} else if (ftp_active(&fp)) {
		sport = htons(FTP_DATA_PORT);
		dstip = &fp.fcp_addr;
	} else {
		return;
	}

	ftp_alg_tuple_insert(ftp, npc, parent, srcip, sport,
		dstip, dport, fp.fcp_flags, NULL);
}

/*
 * Session init
 */
int ftp_alg_session_init(struct npf_session *se, struct npf_cache *npc,
			 struct apt_tuple *nt, const int di)
{
	npf_session_t *parent;
	uint32_t alg_flags;
	int rc = 0;

	switch (apt_tuple_get_table_type(nt)) {
	case APT_MATCH_DPORT:
		/* Parent flow */
		npf_alg_session_set_inspect(se, true);
		npf_alg_session_set_flag(se, FTP_ALG_CNTL);
		break;

	case APT_MATCH_ALL:
	case APT_MATCH_ANY_SPORT:
		/* Child flow */
		parent = apt_tuple_get_active_session(nt);
		if (!parent) {
			rc = -ENOENT;
			break;
		}

		rc = npf_alg_session_nat(se, npf_alg_parent_nat(parent),
					 npc, di, nt, NULL);
		if (!rc) {
			/* Transfer alg_flags from tuple to child session */
			alg_flags = apt_tuple_get_client_flags(nt);
			npf_alg_session_set_flag(se, alg_flags);

			/* Link parent and child sessions */
			npf_session_link_child(parent, se);
		}
		break;

	default:
		rc = -EINVAL;
		break;
	}

	return rc;
}

bool ftp_alg_cntl_session(struct npf_session_alg *sa)
{
	return (sa->sa_flags & FTP_ALG_CNTL) != 0;
}

/* Release reserve if present */
void ftp_alg_session_destroy(struct npf_session *se)
{
	npf_nat_t *nat = npf_alg_session_get_private(se);

	if (nat)
		npf_nat_expire(nat, npf_session_get_vrfid(se));
}

/* Default port config */
static const struct npf_alg_config_item ftp_ports[] = {
	{ IPPROTO_TCP, (NPF_TUPLE_KEEP | NPF_TUPLE_MATCH_PROTO_PORT),
		0, FTP_DEFAULT_PORT }
};

struct npf_alg *npf_alg_ftp_create_instance(struct npf_alg_instance *ai)
{
	struct npf_alg *ftp;
	int rc = -ENOMEM;

	ftp = npf_alg_create_alg(ai, NPF_ALG_ID_FTP);
	if (!ftp)
		goto bad;

	ftp->na_private = NULL;

	/* setup default config */
	ftp->na_num_configs = 1;
	ftp->na_configs[0].ac_items = ftp_ports;
	ftp->na_configs[0].ac_item_cnt = ARRAY_SIZE(ftp_ports);
	ftp->na_configs[0].ac_handler = npf_alg_port_handler;

	rc = npf_alg_register(ftp);
	if (rc)
		goto bad;

	/* Take reference on an alg application instance */
	npf_alg_get(ftp);

	return ftp;

bad:
	if (net_ratelimit())
		RTE_LOG(ERR, FIREWALL, "ALG: FTP instance failed: %d\n", rc);
	free(ftp);
	return NULL;
}

void npf_alg_ftp_destroy_instance(struct npf_alg *ftp)
{
	if (!ftp)
		return;

	/* Expire or delete tuples */
	alg_apt_instance_client_destroy(ftp->na_ai->ai_apt, ftp);

	ftp->na_enabled = false;
	ftp->na_ai = NULL;

	/* Release reference on an alg application instance */
	npf_alg_put(ftp);
}
