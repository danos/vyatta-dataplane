/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdbool.h>
#include <rte_log.h>
#include <czmq.h>
#include <zmq.h>

#include "dp_session.h"
#include "npf/npf_session.h"
#include "npf/npf_nat.h"
#include "npf/npf_nat64.h"
#include "npf/npf_pack.h"
#include "session/session_feature.h"
#include "vplane_debug.h"
#include "vplane_log.h"


static int npf_pack_get_session_from_init_sentry(struct sentry_packet *sp,
						 struct session **cs,
						 struct npf_session **cse)
{
	struct npf_session *se;
	struct session *s;
	bool forw;
	int rc;

	if (!sp)
		return -EINVAL;

	rc = session_lookup_by_sentry_packet(sp, &s, &forw);
	if (rc)
		return rc;

	se = session_feature_get(s, s->se_sen->sen_ifindex,
				 SESSION_FEATURE_NPF);
	if (!se)
		return -ENOENT;

	*cse = se;
	*cs = s;

	return 0;
}

static
int npf_pack_session_unpack_update(struct npf_pack_session_update *csu)
{
	struct npf_pack_session_state *pst;
	struct npf_pack_dp_sess_stats *stats;
	struct npf_pack_sentry_packet *psp;
	struct npf_session *se;
	struct ifnet *ifp;
	struct session *s;
	int rc;

	if (!csu)
		return -EINVAL;

	psp = &csu->psp;
	if (!psp)
		return -EINVAL;

	rc = session_npf_pack_sentry_restore(psp, &ifp);
	if (rc)
		return -EINVAL;

	rc = npf_pack_get_session_from_init_sentry(&psp->psp_forw, &s, &se);
	if (rc)
		goto error;

	if (s && !csu->se_feature_count) {
		session_expire(s, NULL);
		return 0;
	}

	if (s && se) {
		pst = &csu->pst;
		rc = npf_session_npf_pack_state_update(se, pst);
		if (rc)
			goto error;

		stats = &csu->stats;
		rc = session_npf_pack_stats_restore(s, stats);
		if (rc)
			goto error;
	}

	return 0;

 error:
	return rc;
}

static
int npf_pack_restore_session(struct npf_pack_dp_session *pds,
			     struct npf_pack_sentry_packet *psp,
			     struct npf_pack_npf_session *pns,
			     struct npf_pack_session_state *pst,
			     struct npf_pack_dp_sess_stats *stats,
			     struct npf_pack_nat *pnt,
			     struct npf_pack_nat64 *nat64,
			     struct npf_session **npf_se)
{
	struct session *s = NULL;
	struct npf_session *se = NULL;
	struct ifnet *ifp;
	int rc = -EINVAL;

	if (!pds || !psp || !pns || !pst || !stats)
		return rc;

	ifp = dp_ifnet_byifname(psp->psp_ifname);
	if (!ifp) {
		RTE_LOG(ERR, DATAPLANE,
			"npf_pack session %lu restore: Invalid ifname %s\n",
			pds->pds_id, psp->psp_ifname);
		goto error;
	}

	se = npf_session_npf_pack_restore(pns, pst, ifp->if_vrfid,
					  pds->pds_protocol, ifp->if_index);
	if (!se) {
		RTE_LOG(ERR, DATAPLANE,
			"npf_pack npf session restore failed %lu\n",
			pds->pds_id);
		goto error;
	}

	if (pnt) {
		rc = npf_nat_npf_pack_restore(se, pnt, ifp);
		if (rc) {
			RTE_LOG(ERR, DATAPLANE,
				"npf_pack nat session restore failed %lu %s\n",
				pds->pds_id, strerror(-rc));
			goto error;
		}
	}

	if (nat64) {
		rc = npf_nat64_npf_pack_restore(se, nat64);
		if (rc) {
			RTE_LOG(ERR, DATAPLANE,
				"npf_pack nat64 session restore failed %lu %s\n",
				pds->pds_id, strerror(-rc));
			goto error;
		}
	}

	s = session_npf_pack_restore(pds, psp, stats);
	if (!s) {
		RTE_LOG(ERR, DATAPLANE,
			"npf_pack DP session restore failed %lu, %s\n",
			pds->pds_id, strerror(-rc));
		goto error;
	}
	npf_session_set_dp_session(se, s);

	rc = session_feature_add(s, ifp->if_index, SESSION_FEATURE_NPF, se);
	if (rc) {
		RTE_LOG(ERR, DATAPLANE,
			"npf_pack NPF feature add failed %lu, %s\n",
			session_get_id(s), strerror(-rc));
		goto error;
	}

	if (npf_session_npf_pack_activate(se, ifp) != 0) {
		RTE_LOG(ERR, DATAPLANE,
			"npf_pack npf session activate failed %lu\n",
			session_get_id(s));
		goto error;
	}
	*npf_se = se;

	return 0;

 error:
	if (se)
		npf_session_destroy(se);
	if (s)
		session_expire(s, NULL);
	return rc;
}

static int npf_pack_unpack_fw_session(struct npf_pack_session_fw *cs,
				      struct npf_session **se)
{
	return npf_pack_restore_session(&cs->pds, &cs->psp,
					&cs->pns, &cs->pst, &cs->stats,
					NULL, NULL, se);
}

static int npf_pack_unpack_nat_session(struct npf_pack_session_nat *cs,
				       struct npf_session **se)
{
	return npf_pack_restore_session(&cs->pds, &cs->psp,
					&cs->pns, &cs->pst, &cs->stats,
					&cs->pnt, NULL, se);
}

static int npf_pack_unpack_nat64_session(struct npf_pack_session_nat64 *cs,
					 struct npf_session **se)
{
	return npf_pack_restore_session(&cs->pds, &cs->psp,
					&cs->pns, &cs->pst, &cs->stats,
					NULL, &cs->pn64, se);
}

static int
npf_pack_unpack_nat_nat64_session(struct npf_pack_session_nat_nat64 *cs,
				  struct npf_session **se)
{
	return npf_pack_restore_session(&cs->pds, &cs->psp,
					&cs->pns, &cs->pst, &cs->stats,
					&cs->pnt, &cs->pn64, se);
}

static void npf_pack_delete_old_session(struct npf_pack_dp_session *pds,
					struct npf_pack_sentry_packet *psp)
{
	struct session *s = NULL;
	struct npf_session *se = NULL;

	if (!pds || !psp)
		return;

	if (!npf_pack_get_session_from_init_sentry(&psp->psp_forw, &s, &se)) {
		if (s)
			session_expire(s, NULL);
	}
}

static int npf_pack_unpack_one_session(struct npf_pack_session_new *csn,
				       struct npf_session **se)
{
	uint8_t msg_type;
	struct npf_pack_session_hdr *hdr;
	struct npf_pack_session_fw *cs;
	struct npf_pack_sentry_packet *psp;
	struct ifnet *ifp;
	int rc;

	if (!csn)
		return -EINVAL;

	cs = (struct npf_pack_session_fw *)&csn->cs;

	psp = &cs->psp;
	if (!psp)
		return -EINVAL;

	rc = session_npf_pack_sentry_restore(psp, &ifp);
	if (rc)
		return -EINVAL;

	npf_pack_delete_old_session(&cs->pds, psp);
	hdr = &csn->hdr;
	msg_type = hdr->msg_type;

	if (msg_type == NPF_PACK_SESSION_NEW_FW) {
		if (hdr->len < NPF_PACK_NEW_FW_SESSION_SIZE)
			return -EINVAL;
		rc = npf_pack_unpack_fw_session(
			(struct npf_pack_session_fw *)&csn->cs, se);

	} else if (msg_type == NPF_PACK_SESSION_NEW_NAT) {
		if (hdr->len < NPF_PACK_NEW_NAT_SESSION_SIZE)
			return -EINVAL;
		rc = npf_pack_unpack_nat_session(
			(struct npf_pack_session_nat *)&csn->cs, se);

	} else if (msg_type == NPF_PACK_SESSION_NEW_NAT64) {
		if (hdr->len < NPF_PACK_NEW_NAT64_SESSION_SIZE)
			return -EINVAL;
		rc = npf_pack_unpack_nat64_session(
			(struct npf_pack_session_nat64 *)&csn->cs, se);

	} else if (msg_type == NPF_PACK_SESSION_NEW_NAT_NAT64) {
		if (hdr->len < NPF_PACK_NEW_NAT_NAT64_SESSION_SIZE)
			return -EINVAL;
		rc = npf_pack_unpack_nat_nat64_session(
			(struct npf_pack_session_nat_nat64 *)&csn->cs, se);

	} else
		return -EINVAL;

	if (rc)
		return rc;

	return 0;
}

static int npf_pack_unpack_peer_session(struct npf_pack_session_new *csn,
					struct npf_session *se,
					struct npf_session **se_peer)
{
	struct npf_session *sep;
	struct npf_pack_session_new *csn_peer;
	struct npf_pack_session_nat64 *cs;
	struct npf_pack_session_nat64 *cs_peer;
	int rc;

	cs = (struct npf_pack_session_nat64 *)&csn->cs;
	if (!cs->pds.pds_nat64 && !cs->pds.pds_nat46)
		return 0;

	csn_peer = (struct npf_pack_session_new *)((char *)csn + csn->hdr.len);

	rc = npf_pack_unpack_one_session(csn_peer, &sep);
	if (rc || !sep) {
		RTE_LOG(ERR, DATAPLANE,
			"npf_pack peer session restore failed %lu\n",
			cs->pds.pds_id);
		return rc;
	}

	cs_peer = (struct npf_pack_session_nat64 *)&csn_peer->cs;
	if ((cs->pds.pds_parent && cs_peer->pds.pds_parent) ||
	    (!cs->pds.pds_parent && !cs_peer->pds.pds_parent))
		return rc;

	if (cs->pds.pds_parent)
		rc = npf_nat64_session_link(se, sep);
	else
		rc = npf_nat64_session_link(sep, se);
	if (rc)
		return rc;

	*se_peer = sep;
	return 0;
}

static
int npf_pack_session_unpack_new(struct npf_pack_session_new *csn)
{
	struct npf_session *se = NULL;
	struct npf_session *se_peer = NULL;
	int rc;

	if (!csn)
		return -EINVAL;

	rc = npf_pack_unpack_one_session(csn, &se);
	if (rc || !se)
		goto error;

	/* Restore peer session */
	rc = npf_pack_unpack_peer_session(csn, se, &se_peer);
	if (rc)
		goto error;
	return 0;
 error:
	if (se)
		npf_session_destroy(se);
	if (se_peer)
		npf_session_destroy(se_peer);
	return rc;
}

bool npf_pack_validate_msg(struct npf_pack_message *msg, uint32_t size)
{
	struct npf_pack_message_hdr *hdr;

	if (!msg)
		return false;

	if (size > NPF_PACK_MESSAGE_MAX_SIZE ||
	    size < NPF_PACK_MESSAGE_MIN_SIZE)
		return false;

	hdr = &msg->hdr;

	if (!hdr)
		return false;
	if (hdr->pmh_len != size)
		return false;
	if (hdr->pmh_version != SESSION_PACK_VERSION) {
		RTE_LOG(ERR, DATAPLANE,
			"npf_pack unpack: Invalid version %u\n",
			hdr->pmh_version);
		return false;
	}
	if (hdr->pmh_type == SESSION_PACK_FULL) {
		if (size > NPF_PACK_NEW_SESSION_MAX_SIZE)
			return false;
	} else if (hdr->pmh_type == SESSION_PACK_UPDATE) {
		if (size < NPF_PACK_UPDATE_SESSION_SIZE)
			return false;
	} else {
		RTE_LOG(ERR, DATAPLANE,
			"npf_pack unpack: Invalid message type %u\n",
			hdr->pmh_type);
		return false;
	}
	return true;
}

static int npf_pack_unpack_session(void *data, uint32_t size,
				   enum session_pack_type *spt)
{
	struct npf_pack_message *msg = data;
	struct npf_pack_message_hdr *hdr;
	struct npf_pack_session_new *csn;
	struct npf_pack_session_update *csu;
	int rc = -EINVAL;

	*spt = 0;
	if (!npf_pack_validate_msg(msg, size))
		return rc;

	hdr = &msg->hdr;
	*spt = hdr->pmh_type;

	if (hdr->pmh_type == SESSION_PACK_FULL) {
		csn = (struct npf_pack_session_new *)&msg->data.cs_new;
		rc = npf_pack_session_unpack_new(csn);
		if (rc)
			return rc;
	} else if (hdr->pmh_type == SESSION_PACK_UPDATE) {
		csu = &msg->data.cs_update;
		rc = npf_pack_session_unpack_update(csu);
		if (rc)
			return rc;
	}
	return 0;
}

int dp_session_restore(void *buf, uint32_t size, enum session_pack_type *spt)
{
	return npf_pack_unpack_session(buf, size, spt);
}

/* For npf_pack UT */
uint8_t npf_pack_get_msg_type(struct npf_pack_message *msg)
{
	return msg->hdr.pmh_type;
}

/* For npf_pack UT */
uint64_t npf_pack_get_session_id(struct npf_pack_message *msg)
{
	struct npf_pack_message_hdr *hdr;
	struct npf_pack_session_new *csn;
	struct npf_pack_session_update *csu;
	struct npf_pack_dp_session *pds;
	struct npf_pack_session_fw *fw;

	hdr = &msg->hdr;

	if (hdr->pmh_type == SESSION_PACK_FULL) {
		csn = (struct npf_pack_session_new *)&msg->data.cs_new;
		fw = (struct npf_pack_session_fw *)&csn->cs;
		pds = (struct npf_pack_dp_session *)&fw->pds;
		return pds->pds_id;
	} else if (hdr->pmh_type == SESSION_PACK_UPDATE) {
		csu = &msg->data.cs_update;
		return csu->se_id;
	}
	return 0;
}

/* For npf_pack UT */
struct npf_pack_dp_sess_stats *
npf_pack_get_session_stats(struct npf_pack_message *msg)
{
	struct npf_pack_message_hdr *hdr;
	struct npf_pack_session_new *csn;
	struct npf_pack_session_update *csu;
	struct npf_pack_session_fw *fw;

	hdr = &msg->hdr;

	if (hdr->pmh_type == SESSION_PACK_FULL) {
		csn = (struct npf_pack_session_new *)&msg->data.cs_new;
		fw = (struct npf_pack_session_fw *)&csn->cs;
		return &fw->stats;
	} else if (hdr->pmh_type == SESSION_PACK_UPDATE) {
		csu = &msg->data.cs_update;
		return &csu->stats;
	}
	return NULL;
}
