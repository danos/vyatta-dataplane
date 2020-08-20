/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdbool.h>
#include <rte_log.h>

#include "dp_session.h"
#include "npf/npf_session.h"
#include "npf/npf_nat.h"
#include "npf/npf_nat64.h"
#include "npf/npf_pack.h"
#include "session/session_feature.h"
#include "vplane_debug.h"
#include "vplane_log.h"

uint32_t dp_session_buf_size_max(void)
{
	return NPF_PACK_NEW_SESSION_MAX_SIZE;
}

static int npf_pack_session_pack_update(struct session *s,
					struct npf_pack_session_update *csu,
					uint32_t *len)
{
	struct npf_pack_sentry *sen;
	struct npf_pack_session_state *pst;
	struct npf_pack_session_stats *stats;
	struct npf_session *se;
	struct ifnet *ifp;
	int rc;

	if (!s || !csu)
		return -EINVAL;

	csu->se_id = session_get_id(s);
	sen = &csu->sen;
	rc = session_npf_pack_sentry_pack(s, sen);
	if (rc)
		return rc;

	*len = sizeof(*csu);

	stats = &csu->stats;
	rc = session_npf_pack_stats_pack(s, stats);
	if (rc)
		return rc;

	csu->se_feature_count = rte_atomic16_read(&s->se_feature_count);
	if (!csu->se_feature_count)
		return 0;

	ifp = dp_ifnet_byifname(sen->ifname);
	if (!ifp)
		return -EINVAL;
	se = session_feature_get(s, ifp->if_index,
				 SESSION_FEATURE_NPF);
	if (!se) {
		csu->se_feature_count = 0;
		return 0;
	}
	pst = &csu->pst;
	rc = npf_session_npf_pack_state_pack(se, pst);
	if (rc)
		csu->se_feature_count = 0;
	return 0;
}

static int npf_pack_get_new_msg_type(struct session *s, uint8_t *msg_type)
{
	if (!s)
		return -ENOENT;

	if (!session_is_nat(s) && !session_is_nat64(s) && !session_is_nat46(s))
		*msg_type = NPF_PACK_SESSION_NEW_FW;
	else if (session_is_nat(s) && !session_is_nat64(s) &&
		 !session_is_nat46(s))
		*msg_type = NPF_PACK_SESSION_NEW_NAT;
	else if (!session_is_nat(s) && (session_is_nat64(s) ||
					session_is_nat46(s)))
		*msg_type = NPF_PACK_SESSION_NEW_NAT64;
	else if (session_is_nat(s) && (session_is_nat64(s) ||
				       session_is_nat46(s)))
		*msg_type = NPF_PACK_SESSION_NEW_NAT_NAT64;
	else
		return -EINVAL;
	return 0;
}

static int npf_pack_pack_session(struct session *s,
				 struct npf_session *se,
				 struct npf_pack_dp_session *dps,
				 struct npf_pack_sentry *sen,
				 struct npf_pack_npf_session *fw,
				 struct npf_pack_session_state *pst,
				 struct npf_pack_session_stats *stats,
				 struct npf_pack_npf_nat *nat,
				 struct npf_pack_npf_nat64 *nat64)
{
	struct npf_nat *nt;
	struct npf_nat64 *n64;
	int rc;

	if (!s || !se)
		return -EINVAL;

	rc = session_npf_pack_pack(s, dps, sen, stats);
	if (rc) {
		RTE_LOG(ERR, DATAPLANE,
			"npf_pack pack %lu: session pack failed\n",
			session_get_id(s));
		return rc;
	}

	rc = npf_session_npf_pack_pack(se, fw, pst);
	if (rc) {
		RTE_LOG(ERR, DATAPLANE,
			"csycn pack %lu: npf session pack failed\n",
			session_get_id(s));
		return rc;
	}

	if (nat) {
		nt = npf_session_get_nat(se);
		if (!nt)
			return -ENOENT;
		rc = npf_nat_npf_pack_pack(nt, nat, &sen->sp_back);
		if (rc) {
			RTE_LOG(ERR, DATAPLANE,
				"cscyn pack %lu: nat session pack failed\n",
				session_get_id(s));
			return rc;
		}
	}
	if (nat64) {
		n64 = npf_session_get_nat64(se);
		if (!n64)
			return -ENOENT;
		rc = npf_nat64_npf_pack_pack(n64, nat64);
		if (rc) {
			RTE_LOG(ERR, DATAPLANE,
				"cscyn pack %lu: nat64 session pack failed\n",
				session_get_id(s));
			return rc;
		}
	}

	return 0;
}

static int npf_pack_pack_fw_session(struct session *s,
				    struct npf_session *se,
				    struct npf_pack_session_fw *cs)
{
	return npf_pack_pack_session(s, se, &cs->dps, &cs->sen,
				     &cs->se, &cs->pst, &cs->stats,
				     NULL, NULL);
}

static int npf_pack_pack_nat_session(struct session *s,
				     struct npf_session *se,
				     struct npf_pack_session_nat *cs)
{
	return npf_pack_pack_session(s, se, &cs->dps, &cs->sen,
				     &cs->se, &cs->pst, &cs->stats,
				     &cs->nt, NULL);
}

static int npf_pack_pack_nat64_session(struct session *s,
				       struct npf_session *se,
				       struct npf_pack_session_nat64 *cs)
{
	return npf_pack_pack_session(s, se, &cs->dps, &cs->sen,
				     &cs->se, &cs->pst, &cs->stats,
				     NULL, &cs->n64);
}

static int
npf_pack_pack_nat_nat64_session(struct session *s,
				struct npf_session *se,
				struct npf_pack_session_nat_nat64 *cs)
{
	return npf_pack_pack_session(s, se, &cs->dps, &cs->sen,
				     &cs->se, &cs->pst, &cs->stats,
				     &cs->nt, &cs->n64);
}

static int npf_pack_pack_one_session(struct session *s,
				     struct npf_session *se,
				     struct npf_pack_session_new *csn)
{
	uint8_t msg_type = 0;
	int rc;

	if (!s || !csn)
		return -EINVAL;

	rc = npf_pack_get_new_msg_type(s, &msg_type);
	if (rc)
		return rc;
	csn->hdr.msg_type = msg_type;
	if (msg_type == NPF_PACK_SESSION_NEW_FW) {
		csn->hdr.len = NPF_PACK_NEW_FW_SESSION_SIZE;
		rc = npf_pack_pack_fw_session(
			s, se, (struct npf_pack_session_fw *)&csn->cs);
	} else if (msg_type == NPF_PACK_SESSION_NEW_NAT) {
		csn->hdr.len = NPF_PACK_NEW_NAT_SESSION_SIZE;
		rc = npf_pack_pack_nat_session(
			s, se, (struct npf_pack_session_nat *)&csn->cs);
	} else if (msg_type == NPF_PACK_SESSION_NEW_NAT64) {
		csn->hdr.len = NPF_PACK_NEW_NAT64_SESSION_SIZE;
		rc = npf_pack_pack_nat64_session(
			s, se, (struct npf_pack_session_nat64 *)&csn->cs);
	} else if (msg_type == NPF_PACK_SESSION_NEW_NAT_NAT64) {
		csn->hdr.len = NPF_PACK_NEW_NAT_NAT64_SESSION_SIZE;
		rc = npf_pack_pack_nat_nat64_session(
			s, se,
			(struct npf_pack_session_nat_nat64 *)&csn->cs);
	} else
		return -EINVAL;
	if (rc)
		return rc;

	return 0;
}

static int npf_pack_pack_get_peer(struct npf_session *se,
				  struct session **s_peer,
				  struct npf_session **se_peer)
{
	struct npf_nat64 *n64;
	struct session *sp;
	struct npf_session *sep;
	int rc = -ENOENT;

	n64 = npf_session_get_nat64(se);
	if (!n64)
		return rc;
	if (!npf_nat64_has_peer(n64) || !npf_nat64_is_linked(n64))
		return rc;

	sep = npf_nat64_get_peer(n64);
	if (!sep)
		return rc;

	sp = npf_session_get_dp_session(sep);
	if (!sp)
		return rc;

	*s_peer = sp;
	*se_peer = sep;
	return 0;
}

static int npf_pack_pack_peer_session(struct session *s,
				      struct npf_pack_session_new *csn,
				      struct npf_pack_session_new *csn_peer,
				      struct session *s_peer,
				      struct npf_session *se_peer)
{
	struct npf_pack_session_nat64 *cs;
	struct npf_pack_session_nat64 *cs_peer;
	int rc;

	rc = npf_pack_pack_one_session(s_peer, se_peer, csn_peer);
	if (rc) {
		RTE_LOG(ERR, DATAPLANE,
			"npf_pack nat64 peer pack failed %lu\n",
			session_get_id(s_peer));
		return rc;
	}

	/* Set parent */
	cs = (struct npf_pack_session_nat64 *)&csn->cs;
	cs_peer = (struct npf_pack_session_nat64 *)&csn_peer->cs;
	if (session_base_parent(s_peer) == s && session_base_parent(s) == s) {
		cs->dps.se_parent = 1;
	} else if (session_base_parent(s) == s_peer &&
		   session_base_parent(s_peer) == s_peer) {
		cs_peer->dps.se_parent = 1;
	} else {
		RTE_LOG(ERR, DATAPLANE,
			"npf_pack nat64 peer pack failed %lu, parent se link error\n",
			session_get_id(s_peer));
		return -EINVAL;
	}

	return 0;
}

static int npf_pack_session_pack_new(struct session *s,
				     struct npf_pack_session_new *csn,
				     uint32_t *len,
				     struct session **peer)
{
	struct npf_pack_session_new *csn_peer;
	struct session *s_peer = NULL;
	struct npf_session *se_peer = NULL;
	npf_session_t *se;
	int rc;

	*len = 0;

	if (!s || !csn)
		return -EINVAL;

	se = session_feature_get(s, s->se_sen->sen_ifindex,
				 SESSION_FEATURE_NPF);
	if (!se)
		return -ENOENT;

	rc = npf_pack_pack_one_session(s, se, csn);
	if (rc) {
		RTE_LOG(ERR, DATAPLANE,
			"npf_pack pack %lu: session pack failed\n",
			session_get_id(s));
		return rc;
	}
	*len += csn->hdr.len;

	*peer = NULL;
	if (!session_is_nat64(s) && !session_is_nat46(s))
		return 0;

	rc = npf_pack_pack_get_peer(se, &s_peer, &se_peer);
	if (rc) {
		RTE_LOG(ERR, DATAPLANE,
			"npf_pack pack %lu: session peer not found for NAT64 session\n",
			session_get_id(s));
		return rc;
	}
	/* Pack peer session */
	csn_peer = (struct npf_pack_session_new *)((char *)csn + csn->hdr.len);
	rc = npf_pack_pack_peer_session(s, csn, csn_peer, s_peer, se_peer);
	if (rc) {
		RTE_LOG(ERR, DATAPLANE,
			"npf_pack pack %lu: session pack failed\n",
			session_get_id(s));
		return rc;
	}
	*len += csn_peer->hdr.len;
	*peer = s_peer;

	return 0;
}


static int session_pack_full(struct session *s, void *buf, uint32_t size,
			     uint32_t *packed_size, struct session **s_peer)
{
	struct npf_pack_session_new *ps_new = buf;

	*s_peer = NULL;

	if (size < sizeof(struct npf_pack_session_new))
		return -EINVAL;

	*packed_size = 0;
	return npf_pack_session_pack_new(s, ps_new, packed_size, s_peer);
}

static int session_pack_update(struct session *s, void *buf, uint32_t size,
			       uint32_t *packed_size)
{
	struct npf_pack_session_update *ps_update = buf;

	if (size < sizeof(struct npf_pack_session_update))
		return -EINVAL;

	*packed_size = 0;
	return npf_pack_session_pack_update(s, ps_update, packed_size);
}

int dp_session_pack(struct session *session, void *buf, uint32_t size,
		    enum session_pack_type spt, struct session **session_peer)
{
	struct npf_pack_message *msg = buf;
	uint32_t dsize = size - sizeof(msg->hdr);
	uint32_t dlen = 0;
	int ret = -EINVAL;

	*session_peer = NULL;

	if (!session || (size < sizeof(msg->hdr))
	    || (spt != SESSION_PACK_FULL && spt != SESSION_PACK_UPDATE))
		return ret;

	switch (spt) {
	case SESSION_PACK_FULL:
		ret = session_pack_full(session, &msg->data, dsize,
					&dlen, session_peer);
		break;
	case SESSION_PACK_UPDATE:
		ret = session_pack_update(session, &msg->data, dsize, &dlen);
		break;
	default:
		RTE_LOG(ERR, DATAPLANE, "%s: Invalid pack_type %d", __func__,
			spt);
		return ret;
	}

	if (ret == 0) {
		msg->hdr.len = dlen + sizeof(msg->hdr);
		msg->hdr.version = SESSION_PACK_VERSION;
		msg->hdr.msg_type = spt;
		return (int)msg->hdr.len;
	}

	if (ret == -EINVAL && dsize < dlen) {
		dlen += sizeof(msg->hdr);
		RTE_LOG(ERR, DATAPLANE,
			"SESSION_PACK: Buffer too small: session %lu "
			"needed %lu bytes given %u\n",
			session_get_id(session), dlen + sizeof(msg->hdr), size);
	} else
		RTE_LOG(ERR, DATAPLANE,
			"SESSION_PACK:session %lu error %d, len %u\n",
			session_get_id(session), ret, size);

	return ret;
}
