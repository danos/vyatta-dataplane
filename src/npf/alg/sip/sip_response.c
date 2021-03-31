/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * SIP response handilng.
 *
 * Responses are matched to Invite Requests previously save to a hash table.
 * The media contained in the Invite and Response are use to create secondary
 * sessions.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <rte_atomic.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <urcu.h>

#include "dp_event.h"
#include "vrf.h"
#include "util.h"
#include "vplane_log.h"

#include "npf/alg/alg.h"
#include "npf/alg/alg_session.h"
#include "npf/alg/sip/sip.h"
#include "npf/alg/sip/sip_osip.h"

/*
 * sip_tuple_data_alloc() - Alloc a tuple data struct
 */
static struct sip_tuple_data *sip_tuple_data_alloc(const struct npf_alg *sip,
		struct sip_alg_request *sr, struct sip_alg_media *mi,
		struct sip_alg_media *mr)
{
	struct sip_tuple_data *td = calloc(1, sizeof(struct sip_tuple_data));

	if (td) {
		memcpy(&td->td_nat, &sr->sr_nat, sizeof(struct sip_nat));
		td->td_sip = sip;
		td->td_mi = mi;
		td->td_mr = mr;
		rte_atomic32_set(&td->td_refcnt, 0);
		td->td_is_reverse = false;
	}
	return td;
}

/*
 * Free tuple data after last reference has been removed
 */
static void sip_tuple_data_free(struct sip_tuple_data *td)
{
	if (!td)
		return;

	assert(rte_atomic32_read(&td->td_refcnt) == 0);

	if (td->td_mi) {
		sip_media_free(td->td_mi);
		td->td_mi = NULL;
	}
	if (td->td_mr) {
		sip_media_free(td->td_mr);
		td->td_mr = NULL;
	}
	free(td);
}

/*
 * sip_tuple_data_get()
 */
static struct sip_tuple_data *sip_tuple_data_get(struct sip_tuple_data *td)
{
	if (td)
		rte_atomic32_inc(&td->td_refcnt);
	return td;
}

/*
 * sip_tuple_data_put()
 */
static void sip_tuple_data_put(struct sip_tuple_data *td)
{
	if (td && rte_atomic32_dec_and_test(&td->td_refcnt))
		sip_tuple_data_free(td);
}

/*
 * Attach a sip tuple data structure to a tuple, and take a reference on the
 * tuple data.
 */
static void
sip_tuple_data_attach(struct apt_tuple *nt, struct sip_tuple_data *td)
{
	sip_tuple_data_get(td);
	apt_tuple_set_client_data(nt, td);
}

/* Called via ops tuple_delete callback */
void sip_tuple_data_detach(struct apt_tuple *nt)
{
	void *data;

	data = apt_tuple_get_client_data(nt);
	if (data) {
		apt_tuple_set_client_data(nt, NULL);
		sip_tuple_data_put((struct sip_tuple_data *)data);
	}
}

/*
 * sip_alg_handle_error_response()
 */
static bool sip_alg_handle_error_response(const struct npf_alg *sip,
		struct sip_alg_request *sr)
{
	/*
	 * These responses imply a failure and/or a future re-submit of the
	 * invite request, so delete the one we currently have and let
	 * the protocol try again.
	 */
	if (MSG_IS_STATUS_3XX(sr->sr_sip) ||
			MSG_IS_STATUS_4XX(sr->sr_sip) ||
			MSG_IS_STATUS_5XX(sr->sr_sip) ||
			MSG_IS_STATUS_6XX(sr->sr_sip)) {
		sip_request_lookup_and_expire(sip, sr);
		return true;
	}
	return false;
}

static void
sip_alg_tuple_init(struct apt_match_key *m, npf_session_t *se, uint8_t alen)
{
	m->m_ifx = npf_session_get_if_index(se);
	m->m_match = APT_MATCH_ALL;
	m->m_proto = IPPROTO_UDP;
	m->m_alen = alen;
}

/*
 * sip_alg_create_rtp_tuples() - Create the RTP or UDP tuples.  Note that this
 *			traffic is di-directional, so we need to create
 *			one for each possible direction.
 */
static int
sip_alg_create_rtp_tuples(npf_session_t *se, struct npf_alg *sip,
			  struct sip_alg_request *sr, struct sip_alg_media *mi,
			  struct sip_alg_media *mr)
{
	struct sip_tuple_data *td = NULL;
	struct npf_alg_instance *ai = sip->na_ai;
	struct apt_tuple *forward = NULL;
	struct apt_tuple *reverse = NULL;
	struct apt_match_key fwd_m = { 0 }, rev_m = { 0 };
	uint32_t fwd_alg_flags = 0;
	uint32_t rev_alg_flags = 0;


	/*
	 * Set a private data field for the rtp/udp tuples.  This flow
	 * will create tuples for the rtcp flow if needed.
	 *
	 * allocated ports may be reclaimed when the tuples are deleted.
	 */

	td = sip_tuple_data_alloc(sip, sr, mi, mr);
	if (!td) {
		sip_media_free(mi);
		sip_media_free(mr);
		return -ENOMEM;
	}

	/* Common init */
	sip_alg_tuple_init(&fwd_m, se, mi->m_rtp_alen);
	sip_alg_tuple_init(&rev_m, se, mi->m_rtp_alen);

	fwd_alg_flags = SIP_ALG_RTP_FLOW;
	rev_alg_flags = SIP_ALG_RTP_FLOW;

	/* Set ports/addrs/flags */
	switch (td_nat_type(td)) {
	case sip_nat_snat:
		fwd_alg_flags |= SIP_ALG_NAT;
		fwd_m.m_sport = htons(mi->m_rtp_port);
		fwd_m.m_srcip = &mi->m_rtp_addr;
		fwd_m.m_dport = htons(mr->m_rtp_port);
		fwd_m.m_dstip = &mr->m_rtp_addr;

		rev_alg_flags |= SIP_ALG_NAT;
		rev_m.m_sport = htons(mr->m_trtp_port);
		rev_m.m_srcip = &mr->m_trtp_addr;
		rev_m.m_dport = htons(mi->m_trtp_port);
		rev_m.m_dstip = &mi->m_trtp_addr;
		break;
	case sip_nat_dnat:
		fwd_alg_flags |= SIP_ALG_NAT;
		fwd_m.m_sport = htons(mi->m_rtp_port);
		fwd_m.m_srcip = &mi->m_rtp_addr;
		fwd_m.m_dport = htons(mr->m_rtp_port);
		fwd_m.m_dstip = &mr->m_rtp_addr;

		rev_alg_flags |= SIP_ALG_NAT;
		rev_m.m_sport = htons(mr->m_trtp_port);
		rev_m.m_srcip = &mr->m_trtp_addr;
		rev_m.m_dport = htons(mi->m_rtp_port);
		rev_m.m_dstip = &mi->m_rtp_addr;
		break;
	case sip_nat_inspect:
		fwd_m.m_sport = htons(mi->m_rtp_port);
		fwd_m.m_srcip = &mi->m_rtp_addr;
		fwd_m.m_dport = htons(mr->m_rtp_port);
		fwd_m.m_dstip = &mr->m_rtp_addr;

		rev_m.m_sport = htons(mr->m_rtp_port);
		rev_m.m_srcip = &mr->m_rtp_addr;
		rev_m.m_dport = htons(mi->m_rtp_port);
		rev_m.m_dstip = &mi->m_rtp_addr;
		break;
	default:
		sip_tuple_data_free(td);
		return -EINVAL;
	}

	forward = apt_tuple_create_and_insert(ai->ai_apt, &fwd_m,
					      npf_alg_get(sip),
					      fwd_alg_flags, NPF_ALG_SIP_NAME,
					      true, false);
	if (!forward) {
		npf_alg_put(sip);
		sip_tuple_data_free(td);
		return -ENOMEM;
	}

	apt_tuple_set_session(forward, se);

	/* Attach tuple data to forwards tuple */
	sip_tuple_data_attach(forward, td);

	/* Now deal with the reverse tuple */
	rev_alg_flags |= SIP_ALG_REVERSE;

	reverse = apt_tuple_create_and_insert(ai->ai_apt, &rev_m,
					      npf_alg_get(sip),
					      rev_alg_flags, NPF_ALG_SIP_NAME,
					      true, false);
	if (!reverse) {
		npf_alg_put(sip);
		alg_apt_tuple_expire(forward);
		return -ENOMEM;
	}

	apt_tuple_set_session(reverse, se);

	/* Attach tuple data to reverse tuple */
	sip_tuple_data_attach(reverse, td);

	alg_apt_tuple_pair(forward, reverse);

	return 0;
}

/*
 * sip_alg_create_rtcp_tuple()
 */
void sip_alg_create_rtcp_tuples(npf_session_t *se, npf_cache_t *npc,
				struct sip_tuple_data *td)
{
	struct sip_alg_media *mi = td->td_mi;
	struct sip_alg_media *mr = td->td_mr;
	struct npf_alg *sip = npf_alg_session_get_alg(se);
	struct npf_alg_instance *ai = sip->na_ai;
	struct apt_tuple *forward = NULL;
	struct apt_tuple *reverse = NULL;
	struct apt_match_key fwd_m = { 0 }, rev_m = { 0 };
	uint32_t fwd_alg_flags = 0;
	uint32_t rev_alg_flags = 0;

	/*
	 * If the rtcp ports are zero, we have nothing to do.
	 */
	if (!mi->m_rtcp_port || !mr->m_rtcp_port)
		return;

	/*
	 * If this is a UDP SDP proto, then we are done.
	 */
	if (mi->m_proto == sdp_proto_udp)
		return;

	/* Common init */
	sip_alg_tuple_init(&fwd_m, se, npc->npc_alen);
	sip_alg_tuple_init(&rev_m, se, npc->npc_alen);

	fwd_alg_flags = SIP_ALG_RTCP_FLOW;
	rev_alg_flags = SIP_ALG_RTCP_FLOW;

	/* Set ports/addrs/flags */
	switch (td_nat_type(td)) {
	case sip_nat_snat:
		fwd_alg_flags |= SIP_ALG_NAT;
		fwd_m.m_srcip = &mi->m_rtcp_addr;
		fwd_m.m_sport = htons(mi->m_rtcp_port);
		fwd_m.m_dstip = &mr->m_trtcp_addr;
		fwd_m.m_dport = htons(mr->m_trtcp_port);

		rev_alg_flags |= SIP_ALG_NAT;
		rev_m.m_srcip = &mr->m_rtcp_addr;
		rev_m.m_sport = htons(mr->m_rtcp_port);
		rev_m.m_dstip = &mi->m_trtcp_addr;
		rev_m.m_dport = htons(mi->m_trtcp_port);
		break;
	case sip_nat_dnat:
		fwd_alg_flags |= SIP_ALG_NAT;
		fwd_m.m_srcip = &mi->m_rtcp_addr;
		fwd_m.m_sport = htons(mi->m_rtcp_port);
		fwd_m.m_dstip = &mr->m_rtcp_addr;
		fwd_m.m_dport = htons(mr->m_rtcp_port);

		rev_alg_flags |= SIP_ALG_NAT;
		rev_m.m_srcip = &mr->m_trtcp_addr;
		rev_m.m_sport = htons(mr->m_trtcp_port);
		rev_m.m_dstip = &mi->m_rtcp_addr;
		rev_m.m_dport = htons(mi->m_rtcp_port);
		break;
	case sip_nat_inspect:
		fwd_m.m_srcip = &mi->m_rtcp_addr;
		fwd_m.m_sport = htons(mi->m_rtcp_port);
		fwd_m.m_dstip = &mr->m_rtcp_addr;
		fwd_m.m_dport = htons(mr->m_rtcp_port);

		rev_m.m_srcip = &mr->m_rtcp_addr;
		rev_m.m_sport = htons(mr->m_rtcp_port);
		rev_m.m_dstip = &mi->m_rtcp_addr;
		rev_m.m_dport = htons(mi->m_rtcp_port);
		break;
	default:
		return;
	}

	forward = apt_tuple_create_and_insert(ai->ai_apt, &fwd_m,
					      npf_alg_get(sip),
					      fwd_alg_flags, NPF_ALG_SIP_NAME,
					      true, false);
	if (!forward) {
		npf_alg_put(sip);
		return;
	}

	apt_tuple_set_session(forward, se);

	/* Attach tuple data to forwards tuple */
	sip_tuple_data_attach(forward, td);

	/* Now deal with the reverse tuple */
	rev_alg_flags |= SIP_ALG_REVERSE;

	reverse = apt_tuple_create_and_insert(ai->ai_apt, &rev_m,
					      npf_alg_get(sip),
					      rev_alg_flags, NPF_ALG_SIP_NAME,
					      true, false);
	if (!reverse) {
		npf_alg_put(sip);
		alg_apt_tuple_expire(forward);
		return;
	}

	apt_tuple_set_session(reverse, se);

	/* Attach tuple data to reverse tuple */
	sip_tuple_data_attach(reverse, td);

	alg_apt_tuple_pair(forward, reverse);

}

/*
 * sip_alg_resolve_media() - sync up invite/response and create tuples.
 */
static int sip_alg_resolve_media(npf_session_t *se,
		struct sip_alg_request *invite,
		struct sip_alg_request *response)
{
	int rc = 0;
	int pos;
	struct npf_alg *sip = npf_alg_session_get_alg(se);
	int size = sip_media_count(&invite->sr_media_list_head);

	/*
	 * If the invite and response port lists are different sizes,
	 * then we had a bad SDP packet in either - They must be the
	 * same size.
	 */
	if (size != sip_media_count(&response->sr_media_list_head))
		return -1;

	/*
	 * Prepare for creating tuples out of each media definition
	 * from the invite and response.
	 */
	for (pos = 0; pos < size; pos++) {
		struct sip_alg_media  *i;
		struct sip_alg_media  *r;

		i = cds_list_first_entry(&invite->sr_media_list_head,
					struct sip_alg_media, m_node);
		cds_list_del(&i->m_node);

		r = cds_list_first_entry(&response->sr_media_list_head,
					struct sip_alg_media, m_node);
		cds_list_del(&r->m_node);

		/* This consumes the medias */
		rc = sip_alg_create_rtp_tuples(se, sip, invite, i, r);
		if (rc)
			break;
	}

	return rc;
}

/*
 * Verify that the call ID in 'sr' matches the given session.
 */
static bool sip_alg_verify_session_call_id(npf_session_t *se,
					   struct sip_alg_request *sr)
{
	osip_call_id_t *cid;
	struct sip_alg_session *ss;
	int i;

	/* Only CNTL sessions have private data */
	ss = npf_alg_session_get_private(se);
	if (!ss)
		return false;

	cid = osip_message_get_call_id(sr->sr_sip);
	if (!cid)
		return false;

	for (i = 0; i < ss->ss_call_id_count; i++) {
		if (osip_call_id_match(cid, ss->ss_call_ids[i])
							== OSIP_SUCCESS)
			return true;
	}
	return false;
}

/*
 * Manage all sip responses.
 *
 * Here we associate the previously received INVITE (if applicable) with this
 * 200 or 183 response, and eventually create the rtp tuples for the media
 * flows.
 *
 * A '183 Session Progress' may be used if early media (RTP traffic before the
 * call is answered) is present.  This response (like the '200 OK') includes
 * an SDP message part containing media information.
 *
 * The first response received containing SDP media information is used to
 * create the RTP/RTCP tuples.  After that, we can expire the SIP Request
 * message that we have been holding onto.
 *
 * However if the original Invite is expired upon receipt of a 183 message
 * then we still need to ensure that we translate the SDP media fields in the
 * '200 OK' message.
 *
 * (Early media typically includes dial tones and/or recorded messages.)
 *
 * Note we also do some sanity checking on this response and we can return an
 * error to drop the packet.
 */
int sip_manage_response(npf_session_t *se, npf_cache_t *npc,
			struct sip_alg_request *sr,
			struct sip_alg_request *tsr, npf_nat_t *nat)

{
	struct sip_alg_request *osr;
	struct npf_alg *sip = npf_alg_session_get_alg(se);
	int rc;

	/* Set per-packet info */
	npc->npc_alg_flags = SIP_NPC_RESPONSE;

	/*
	 * Handle all error responses now, no need to continue
	 * if this is an error response.
	 */
	if (sip_alg_handle_error_response(sip, tsr))
		return 0;

	/*
	 * If this is a '200 Ok', or a '183 Session Progress', then we
	 * may need to resolve the media flows for this sip call.
	 */
	rc = 0;
	if (MSG_IS_RESPONSE_FOR(tsr->sr_sip, "INVITE") &&
			(MSG_TEST_CODE(tsr->sr_sip, 200) ||
			 MSG_TEST_CODE(tsr->sr_sip, 183))) {

		/*
		 * We are only interested in backwards Responses,
		 * eg: reply to a forward request
		 */
		if (sip_forw(tsr))
			return 0;

		/* ignore non-sdp 200 responses */
		if (!sr->sr_sdp && MSG_TEST_CODE(tsr->sr_sip, 200))
			return 0;

		/* But not 183's... */
		if (!sr->sr_sdp && MSG_TEST_CODE(tsr->sr_sip, 183))
			return -EINVAL;

		osr = sip_request_lookup(sip, sr);
		if (osr) {
			/* Translate SDP media fields */
			rc = sip_alg_manage_media(se, nat, tsr);
			if (!rc)
				rc = sip_alg_resolve_media(se, osr, tsr);

			/* Always expire the INVITE, UA can resend */
			sip_request_expire(osr);
		} else {
			/*
			 * The original INVITE may have been resolved by a 183
			 * Response.  If so, we still need to translate the
			 * SDP media in the '200 OK' message.  Verify the
			 * call-ID matches the session before doing so.
			 */
			if (!MSG_TEST_CODE(tsr->sr_sip, 200))
				return 0;

			if (!sip_alg_verify_session_call_id(se, sr))
				return 0;

			rc = sip_alg_manage_media(se, nat, tsr);
		}
	}

	return rc;
}

