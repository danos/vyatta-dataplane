/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdbool.h>
#include <rte_log.h>

#include "session/session.h"
#include "session/session_pack_pb.h"
#include "vplane_debug.h"

/*
 * Pack a group of bit-fields from struct session into a single uint32 field
 * ss_flag in DPSessionMessage. Having a set of individual boolean bit fields
 * is costly (2 bytes per boolean) in Protobuf message encoding, It is more
 * efficient to use a single field for a group of flags.
 *
 * Field naming:
 * psf_<name> corresponds to se_<name> in struct session.
 */
struct pb_session_flags {
	union {
		struct {
			uint32_t	psf_flags:16;
			uint32_t	psf_fw:1;
			uint32_t	psf_snat:1;
			uint32_t	psf_dnat:1;
			uint32_t	psf_nat64:1;
			uint32_t	psf_nat46:1;
			uint32_t	psf_alg:1;
			uint32_t	psf_in:1;
			uint32_t	psf_out:1;
			uint32_t	psf_app:1;
		} psf_bits;
		uint32_t	psf_allbits;
	};
};

/* pack session bit fields to an uint32_t */
static void session_pack_flags(struct session *s, uint32_t *flags)
{
	struct pb_session_flags psf = { .psf_allbits = 0 };

	psf.psf_bits.psf_flags = s->se_flags;
	psf.psf_bits.psf_fw = s->se_fw;
	psf.psf_bits.psf_snat = s->se_snat;
	psf.psf_bits.psf_dnat = s->se_dnat;
	psf.psf_bits.psf_nat64 = s->se_nat64;
	psf.psf_bits.psf_nat46 = s->se_nat46;
	psf.psf_bits.psf_alg = s->se_alg;
	psf.psf_bits.psf_in = s->se_in;
	psf.psf_bits.psf_out = s->se_out;
	psf.psf_bits.psf_app = s->se_app;

	*flags = psf.psf_allbits;
}

/* unpack an uint32_t to set the session's bit fields */
static void session_restore_flags(struct session *s, uint32_t flags)
{
	struct pb_session_flags psf = { .psf_allbits = flags };

	s->se_flags = psf.psf_bits.psf_flags;
	s->se_fw = psf.psf_bits.psf_fw;
	s->se_snat = psf.psf_bits.psf_snat;
	s->se_dnat = psf.psf_bits.psf_dnat;
	s->se_nat64 = psf.psf_bits.psf_nat64;
	s->se_nat46 = psf.psf_bits.psf_nat46;
	s->se_alg = psf.psf_bits.psf_alg;
	s->se_in = psf.psf_bits.psf_in;
	s->se_out = psf.psf_bits.psf_out;
	s->se_app = psf.psf_bits.psf_app;
}

/*
 * Copy session's sentry to protobuf-c DPSessionKeyMsg struct.
 * DPSessionKeyMsg is equivalent to the forward sentry_packet information.
 * Only the forward addrid key is used since the reverse addrid can be
 * constructed from the forward addrid keys.
 */
int session_pack_sentry_pb(struct session *s, DPSessionKeyMsg *sk)
{
	const struct sentry *sen;
	const struct ifnet *ifp;
	const char *ifname;
	int i;

	if (!s || !sk)
		return -EINVAL;

	sen = rcu_dereference(s->se_sen);
	if (!sen)
		return -ENOENT;

	ifp = dp_ifnet_byifindex(sen->sen_ifindex);
	if (!ifp)
		return -ENOENT;
	ifname = dp_ifnet_ifname(ifp);
	memcpy(sk->sk_ifname, ifname, IFNAMSIZ);

	sk->has_sk_flags = 1;
	sk->sk_flags = sen->sen_flags;

	sk->has_sk_protocol = 1;
	sk->sk_protocol = sen->sen_protocol;

	sk->n_sk_addrids = sen->sen_len;
	for (i = 0; i < sen->sen_len; ++i)
		sk->sk_addrids[i] = sen->sen_addrids[i];

	return 0;
}

/* restore forward sentry_packet from protobuf-c DPSessionKeyMsg.
 * This sentry_packet is used to lookup the restored session in sentry tables.
 */
int session_restore_sentry_packet_pb(struct sentry_packet *sp,
				     const struct ifnet *ifp,
				     DPSessionKeyMsg *sk)
{
	size_t i;

	if (!sp || !sk || !ifp)
		return -EINVAL;

	if (!sk->has_sk_protocol || !sk->n_sk_addrids)
		return -EINVAL;

	sp->sp_vrfid = ifp->if_vrfid;
	sp->sp_ifindex = ifp->if_index;
	if (sk->has_sk_flags)
		sp->sp_sentry_flags = sk->sk_flags;
	else
		sp->sp_sentry_flags = 0;

	sp->sp_protocol = sk->sk_protocol;
	sp->sp_len = sk->n_sk_addrids;

	for (i = 0; i < sk->n_sk_addrids; ++i)
		sp->sp_addrids[i] = sk->sk_addrids[i];

	return 0;
}

/* pack  session timeouts, state, and flags to protobuf message */
static int session_pack_state_pb(struct session *s, DPSessionStateMsg *ssm)
{
	if (!s || !ssm)
		return -EINVAL;

	ssm->has_ss_custom_timeout = 1;
	ssm->ss_custom_timeout = s->se_custom_timeout;
	ssm->has_ss_timeout = 1;
	ssm->ss_timeout = s->se_timeout;
	ssm->has_ss_protocol_state = 1;
	ssm->ss_protocol_state = s->se_protocol_state;
	ssm->has_ss_generic_state = 1;
	ssm->ss_generic_state = s->se_gen_state;
	ssm->has_ss_flags = 1;
	session_pack_flags(s, &ssm->ss_flags);

	return 0;
}

/* Restore session timeouts, state, and flags from protobuf message */
int session_restore_state_pb(struct session *s, DPSessionStateMsg *ssm)
{
	if (!s || !ssm)
		return -EINVAL;

	if (!ssm->has_ss_custom_timeout || !ssm->has_ss_timeout ||
	    !ssm->has_ss_protocol_state || !ssm->has_ss_generic_state ||
	    !ssm->has_ss_flags)
		return -EINVAL;

	s->se_custom_timeout = ssm->ss_custom_timeout;
	s->se_timeout = ssm->ss_timeout;
	s->se_protocol_state = ssm->ss_protocol_state;
	s->se_gen_state = ssm->ss_generic_state;

	session_restore_flags(s, ssm->ss_flags);

	return 0;
}

/* Copy session counters to protobuf-c DPSessionCounterMsg struct */
static int session_pack_counters_pb(struct session *s, DPSessionCounterMsg *scm)
{
	if (!s || !scm)
		return -EINVAL;

	scm->has_sc_pkts_in = 1;
	scm->sc_pkts_in = rte_atomic64_read(&s->se_pkts_in);
	scm->has_sc_bytes_in = 1;
	scm->sc_bytes_in = rte_atomic64_read(&s->se_bytes_in);
	scm->has_sc_pkts_out = 1;
	scm->sc_pkts_out = rte_atomic64_read(&s->se_pkts_out);
	scm->has_sc_bytes_out = 1;
	scm->sc_bytes_out = rte_atomic64_read(&s->se_bytes_out);

	return 0;
}

/* Restore session counters from protobuf message */
int session_restore_counters_pb(struct session *s, DPSessionCounterMsg *scm)
{
	if (!s || !scm)
		return -EINVAL;

	if (!scm->has_sc_pkts_in || !scm->has_sc_bytes_in ||
	    !scm->has_sc_pkts_out || !scm->has_sc_bytes_out)
		return -EINVAL;

	rte_atomic64_set(&s->se_pkts_in, scm->sc_pkts_in);
	rte_atomic64_set(&s->se_bytes_in, scm->sc_bytes_in);
	rte_atomic64_set(&s->se_pkts_out, scm->sc_pkts_out);
	rte_atomic64_set(&s->se_bytes_out, scm->sc_bytes_out);

	return 0;
}

/*
 * Copy a session to procbuf-c DPSessionMsg struct.
 *
 * All messages/strings/byte fields in the DPSessionMsg
 * message structure must already be allocated before.
 */
int session_pack_pb(struct session *s, DPSessionMsg *dpsm)
{
	int rc;

	if (!s || !dpsm)
		return -EINVAL;

	dpsm->has_ds_id = 1;
	dpsm->ds_id = s->se_id;

	rc = session_pack_sentry_pb(s, dpsm->ds_key);
	if (rc < 0)
		return rc;

	rc = session_pack_state_pb(s, dpsm->ds_state);
	if (rc < 0)
		return rc;

	rc = session_pack_counters_pb(s, dpsm->ds_counters);
	if (rc < 0)
		return rc;

	return 0;
}

/*Allocate and restore a session's state from a protobuf message */
struct session *session_restore_pb(DPSessionMsg *dpsm, struct ifnet *ifp,
				   uint8_t protocol)
{
	struct session *s;
	int rc;

	if (!dpsm || !ifp)
		return NULL;

	if (!dpsm->ds_state)
		return NULL;

	s = session_alloc();
	if (!s)
		return NULL;

	rc = session_restore_state_pb(s, dpsm->ds_state);
	if (rc < 0)
		goto error;

	rc = session_restore_counters_pb(s, dpsm->ds_counters);
	if (rc < 0)
		goto error;

	s->se_vrfid = ifp->if_vrfid;
	s->se_protocol = protocol;

	return s;
error:
	session_reclaim(s);
	return NULL;
}
