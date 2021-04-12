/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
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
#include "npf/npf_state.h"
#include "protobuf/SessionPack.pb-c.h"
#include "session/session_feature.h"
#include "session/session_pack_pb.h"
#include "vplane_debug.h"
#include "vplane_log.h"

/*
 * Copy a session and its npf_session to DPSessionMsg struct.
 */
static int npf_pack_full_pb(struct session *s, DPSessionMsg *dpsm)
{
	npf_session_t *se;
	struct sentry *sen;

	if (!s || !dpsm)
		return -EINVAL;

	sen = rcu_dereference(s->se_sen);
	if (!sen)
		return -ENOENT;

	se = session_feature_get(s, sen->sen_ifindex, SESSION_FEATURE_NPF);
	if (!se)
		return -ENOENT;

	session_pack_pb(s, dpsm);
	npf_session_pack_pb(se, dpsm->ds_npf_session);
	return 0;
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

	rc = npf_pack_full_pb(s, &dps);
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
