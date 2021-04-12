/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdbool.h>
#include <rte_log.h>

#include "dp_session.h"
#include "npf/npf_session.h"
#include "npf/npf_pack.h"
#include "protobuf/SessionPack.pb-c.h"
#include "session/session_feature.h"
#include "session/session_pack_pb.h"
#include "vplane_debug.h"
#include "vplane_log.h"

/*
 * Copy a session and its npf_session to DPSessionMsg struct.
 * full_copy indicates if a fully restorable session is being copied,
 * or this function is copying only the information needed to update
 * a previously restored session.
 *
 * with full_copy == true,
 *  - copy sentry
 *  - copy states and counters from the dataplane session
 *  - copy npf_session, if no npf_session found return -ENOENT.
 * with full_copy == false:
 *  - copy sentry
 *  - copy dataplane session counters
 *  - copy npf_session, if no npf_session set dpsm->ds_npf_session to NULL
 *    indicating the session has expired.
 */
static int npf_pack_session_pb(struct session *s,
			       DPSessionMsg *dpsm,
			       bool full_copy)
{
	npf_session_t *se;
	struct sentry *sen;
	int rc;

	if (!s || !dpsm)
		return -EINVAL;

	sen = rcu_dereference(s->se_sen);
	if (!sen)
		return -ENOENT;

	se = session_feature_get(s, sen->sen_ifindex, SESSION_FEATURE_NPF);
	if (full_copy && !se)
		return -ENOENT;

	rc = session_pack_pb(s, dpsm, full_copy);
	if (rc)
		return rc;

	if (se)
		rc = npf_session_pack_pb(se, dpsm->ds_npf_session);

	if (!se || rc)
		dpsm->ds_npf_session = NULL; /* indicate no npf_session */

	/* partial copies are successful even if there is no npf_session or
	 * npf_session couldn't be packed.
	 */
	return full_copy ? rc : 0;
}

/*
 * Fills up the pb_buf with a packed protobuf PackedDPSessionMsg message.
 *
 * define a fully initialized PackedDPSessionMsg structure on stack, pass it to
 * function to copy information from the struct session to be packed. Make sure
 * all pointers to sub messages, repeated fields, strings are pointing to valid
 * memory.
 *
 * returns the length of the packed buffer on success. return error codes on
 * failure.
 */
static int npf_pack_pb(struct session *s, void *pb_buf, size_t size,
		       enum session_pack_type spt, uint8_t *flags,
		       struct session **peer)
{
	PackedDPSessionMsg pds = PACKED_DPSESSION_MSG__INIT;
	DPSessionMsg dps = DPSESSION_MSG__INIT;
	DPSessionMsg *dps_ptr[1] = {&dps, };
	DPSessionKeyMsg sk = DPSESSION_KEY_MSG__INIT;
	DPSessionStateMsg dps_state = DPSESSION_STATE_MSG__INIT;
	DPSessionCounterMsg dps_counters = DPSESSION_COUNTER_MSG__INIT;
	NPFSessionMsg npfsm = NPFSESSION_MSG__INIT;
	NPFSessionStateMsg npfssm = NPFSESSION_STATE_MSG__INIT;
	TCPWindowMsg tcpwinarray[NPF_FLOW_SZ];
	TCPWindowMsg * tcpwinptrs[NPF_FLOW_SZ];
	char ifname[IFNAMSIZ] = {0,};
	uint32_t addrids[SENTRY_LEN_IPV6] = {0,};

	int i;
	int rc;
	size_t packed_size;

	/*
	 * Right now packing is supported only on firewall sessions
	 */
	if (session_is_nat(s) || session_is_nat64(s) ||
	    session_is_nat46(s) || session_is_alg(s) ||
	    session_is_app(s))
		return -ENOTSUP;

	/* Set up message for packing */
	sk.sk_ifname = ifname;
	sk.sk_addrids = addrids;
	dps.ds_key = &sk;
	dps.ds_state = &dps_state;
	dps.ds_counters = &dps_counters;

	for (i = 0; i < NPF_FLOW_SZ; ++i) {
		tcpwindow_msg__init(&tcpwinarray[i]);
		tcpwinptrs[i] = &tcpwinarray[i];
	}
	npfssm.nss_tcpwins = tcpwinptrs;
	npfsm.ns_state = &npfssm;
	dps.ds_npf_session = &npfsm;

	pds.has_pds_pack_type = 1;
	pds.pds_pack_type = spt;

	/* Packs a single session */
	rc = npf_pack_session_pb(s, &dps, spt == SESSION_PACK_FULL);

	if (rc < 0)
		return rc;

	pds.has_pds_flags = 1;
	pds.pds_flags = SESSION_TYPE_FW;
	pds.n_pds_sessions = 1;
	pds.pds_sessions = dps_ptr;

	packed_size = packed_dpsession_msg__get_packed_size(&pds);
	if (size < packed_size) {
		RTE_LOG(ERR, FIREWALL,
			"too small buffer need %zi got %zu\n",
			packed_size, size);
		return -ENOSPC;
	}

	*peer = NULL;
	*flags = pds.pds_flags;
	return (int)packed_dpsession_msg__pack(&pds, pb_buf);
}

int dp_session_pack_pb(struct session *session,
		       void *buf, uint32_t size,
		       enum session_pack_type spt,
		       struct session **session_peer)
{
	int rc;
	struct dp_session_pack_hdr *sph = buf;
	uint8_t flags;

	if (size < sizeof(*sph))
		return -ENOSPC;

	if (spt != SESSION_PACK_FULL && spt != SESSION_PACK_UPDATE)
		return -EINVAL;

	rc = npf_pack_pb(session,
			 &sph[1], size - sizeof(*sph),
			 spt, &flags, session_peer);
	if (rc < 0)
		return rc;

	sph->sph_len = rc + sizeof(*sph);
	sph->sph_version = NPF_PACK_PB_VERSION;
	sph->sph_flags = flags;
	sph->sph_type = spt;
	return sph->sph_len;
}

PackedDPSessionMsg *npf_unpack_pb(void *buf, uint32_t size)
{
	PackedDPSessionMsg *pds = NULL;
	struct dp_session_pack_hdr *sph = buf;
	const uint8_t *pb_buf = (const uint8_t *)buf + sizeof(*sph);

	if (!sph || sph->sph_len > size)
		return NULL;

	pds = packed_dpsession_msg__unpack(NULL, size - sizeof(*sph), pb_buf);

	if (!pds) {
		RTE_LOG(ERR, DATAPLANE,
			"SESSION_RESTORE: Invalid protobuf(size=%u)\n",
			size);
		return NULL;
	}

	if (!pds->n_pds_sessions) {
		RTE_LOG(ERR, DATAPLANE,
			"SESSION_RESTORE: no encoded sessions in protobuf\n");
		goto error;
	}

	if (!pds->has_pds_pack_type) {
		RTE_LOG(ERR, DATAPLANE,
			"SESSION_RESTORE: no pack_type protobuf\n");
		goto error;
	}
	return pds;
error:
	packed_dpsession_msg__free_unpacked(pds, NULL);
	return NULL;

}

void npf_unpack_free_pb(PackedDPSessionMsg *pds)
{
	if (pds)
		packed_dpsession_msg__free_unpacked(pds, NULL);
}

/*
 * restore a single session.
 */
static int
dp_session_msg_restore(DPSessionMsg *dpsm, enum session_pack_type spt,
		       struct session **rs, struct npf_session **rns)
{
	DPSessionKeyMsg *skm;
	struct ifnet *ifp = NULL;
	struct npf_session *se = NULL;
	struct session *s = NULL;
	struct sentry_packet sp_forw;
	struct sentry_packet sp_back;
	bool forw;
	int rc;

	if (!dpsm || !dpsm->ds_npf_session || !dpsm->ds_key)
		return -EINVAL;

	skm = dpsm->ds_key;

	if (skm->sk_ifname)
		ifp = dp_ifnet_byifname(skm->sk_ifname);
	else
		return -EINVAL;

	if (!ifp) {
		RTE_LOG(ERR, DATAPLANE,
			"SESSION_RESTORE: Failed to find interface %s\n",
			skm->sk_ifname);
		return -ENOENT;
	}

	rc = session_restore_sentry_packet_pb(&sp_forw, ifp, skm);
	if (rc)
		return -EINVAL;

	rc = session_lookup_by_sentry_packet(&sp_forw, &s, &forw);
	switch (spt) {
	case SESSION_PACK_FULL:
		if (!rc && s)
			session_expire(s, NULL);
		break;
	case SESSION_PACK_UPDATE:
		return -ENOTSUP;
	case SESSION_PACK_NONE:
		return -EINVAL;
	}

	se = npf_session_restore_pb(dpsm->ds_npf_session,
			ifp, skm->sk_protocol);
	if (!se) {
		RTE_LOG(ERR, DATAPLANE,
			"npf session restore failed %lu\n", dpsm->ds_id);
		return -ENOMEM;
	}

	s = session_restore_pb(dpsm, ifp, sp_forw.sp_protocol);
	if (!s) {
		RTE_LOG(ERR, DATAPLANE,
			"session restore failed %lu\n", dpsm->ds_id);
		rc = -ENOMEM;
		goto error;
	}

	sentry_packet_reverse(&sp_forw, &sp_back);
	rc = session_insert_restored(s, &sp_forw, &sp_back);
	if (rc)
		goto error;

	npf_session_set_dp_session(se, s);

	rc = session_feature_add(s, ifp->if_index, SESSION_FEATURE_NPF, se);
	if (rc) {
		RTE_LOG(ERR, DATAPLANE,
			"npf_session restore: NPF feature add failed %lu, %s\n",
			session_get_id(s), strerror(-rc));
		goto error;
	}

	rc = npf_session_activate_restored(se, ifp);
	if (rc) {
		RTE_LOG(ERR, DATAPLANE,
			"npf session restore: session activate failed %lu\n",
			session_get_id(s));
		goto error;
	}
	*rns = se;
	*rs = s;
	return 0;
error:
	if (se)
		npf_session_destroy(se);
	if (s)
		session_expire(s, NULL);
	return rc;
}

int npf_pack_restore_pb(void *buf, uint32_t size, enum session_pack_type *spt)
{
	struct session *rs = NULL;
	struct npf_session *rns = NULL;
	int rc = -EINVAL;
	DPSessionMsg *dpsm;
	PackedDPSessionMsg *pds = npf_unpack_pb(buf, size);

	if (pds == NULL) {
		RTE_LOG(ERR, DATAPLANE,
			"SESSION_RESTORE: protobuf unpack failed size = %u\n",
			size);
		return rc;
	}

	*spt = pds->pds_pack_type;
	dpsm = pds->pds_sessions[0];

	rc = dp_session_msg_restore(dpsm, pds->pds_pack_type, &rs, &rns);

	npf_unpack_free_pb(pds);
	return rc;
}

int dp_session_restore(void *buf, uint32_t size, enum session_pack_type *spt)
{
	struct dp_session_pack_hdr *sph = buf;

	if (buf == NULL || size < sizeof(*sph))
		return -EINVAL;

	if (is_npf_pack_pb_version(sph->sph_version))
		return npf_pack_restore_pb(buf, size, spt);

	return npf_pack_restore(buf, size, spt);
}
