/*
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2013-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * NPF ALG for SIP
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <rte_spinlock.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <urcu/list.h>

#include "compiler.h"
#include "in_cksum.h"
#include "npf/npf.h"
#include "npf/alg/alg.h"
#include "npf/npf_cache.h"
#include "npf/npf_nat.h"
#include "npf/npf_session.h"
#include "urcu.h"
#include "util.h"
#include "vplane_log.h"

#include "npf/alg/alg_sip.h"
#include "npf/alg/sip/sip.h"

struct ifnet;
struct rte_mbuf;
struct sip_alg_request;

/* default port */
#define SIP_DEFAULT_PORT	5060

/* For one-time initialization of libosip. */
static osip_t		*sip_osip;


/*
 * sip_addr_from_str() - Convert a string addr into an Ipv4 or IPv6 addr
 */
void sip_addr_from_str(const char *saddr, npf_addr_t *addr, uint8_t *alen)
{
	int af = AF_INET;

	if (strchr(saddr, ':'))
		af = AF_INET6;

	*alen = 0;
	if (inet_pton(af, saddr, addr)) {
		if (af == AF_INET)
			*alen = 4;
		else
			*alen = 16;
	}
}

/*
 * Convert an address to an (allocated) string
 */
char *sip_addr_to_str(npf_addr_t *a, uint8_t alen)
{
	char buf[INET6_ADDRSTRLEN];
	int af;

	if (alen == 4)
		af = AF_INET;
	else if (alen == 16)
		af = AF_INET6;
	else
		return NULL;

	if (inet_ntop(af, a, buf, sizeof(buf)))
		return osip_strdup(buf);
	return NULL;
}

/*
 * Convert a port to an (allocated) string
 */
char *sip_port_to_str(in_port_t n)
{
	char buf[8];
	int rc;

	rc = snprintf(buf, 8, "%hu", n);
	if (rc < 0 || rc > 6)
		return NULL;
	return osip_strdup(buf);
}

static int sip_alg_private_session_init(npf_session_t *se)
{
	struct sip_alg_session *ss;

	ss = npf_alg_session_get_private(se);
	if (ss)
		return -EINVAL;
	ss = calloc(sizeof(struct sip_alg_session), 1);
	if (!ss)
		return -ENOMEM;
	npf_alg_session_set_private(se, ss);

	return 0;
}

static void sip_alg_private_session_free(npf_session_t *se)
{
	struct sip_alg_session *ss;


	ss = npf_alg_session_get_private(se);
	if (ss)
		sip_expire_session_request(se);
	free(ss);
}

/*
 * sip_alg_verify() - Some cursory checks before dealing with this packet.
 */
int sip_alg_verify(struct sip_alg_request *sr)
{
	/*
	 * We only check whether required headers have been
	 * parsed, we do not verify the contents.
	 */
	if (!sr->sr_sip->to)
		return -EINVAL;
	if (!sr->sr_sip->from)
		return -EINVAL;
	if (!sr->sr_sip->cseq)
		return -EINVAL;
	if (!sr->sr_sip->call_id)
		return -EINVAL;
	if (osip_list_size(&sr->sr_sip->vias) < 1)
		return -EINVAL;

	return 0;
}

/* Create an alg nat object */
static struct npf_alg_nat *
sip_create_nat(vrfid_t vrfid, uint32_t flags, bool reserved,
	       npf_addr_t oaddr, in_port_t oport,
	       npf_addr_t taddr, in_port_t tport)
{
	struct npf_alg_nat *an = malloc(sizeof(struct npf_alg_nat));

	if (an) {
		an->an_oaddr = oaddr;
		an->an_oport = oport;
		an->an_taddr = taddr;
		an->an_tport = tport;
		an->an_flags = flags;
		an->an_vrfid = vrfid;
		if (reserved)
			an->an_flags |= NPF_NAT_CLONE_APM | NPF_NAT_MAP_PORT;
	}
	return an;
}

/*
 * Called from sip_alg_session_init when an ALT_CNTL tuple is matched.
 */
static int sip_session_nat_alt_cntl(npf_session_t *se, npf_cache_t *npc,
				    const int di, struct apt_tuple *nt,
				    npf_session_t *parent)
{
	npf_nat_t *pnat;
	npf_addr_t oaddr;
	npf_addr_t taddr;
	in_port_t oport, tport;
	int ntype;
	uint masq;
	struct npf_alg_nat *an;
	struct npf_alg *sip;
	int rc;

	/* Only if parent is natted */
	pnat = npf_session_get_nat(parent);
	if (!pnat)
		return 0;

	/* Get parent NAT translation address and port */
	if (!npf_nat_info(pnat, &ntype, &taddr, &tport, &masq))
		return -EINVAL;

	/* Only for SNAT */
	if (ntype != NPF_NATOUT)
		return -EINVAL;

	/*
	 * All we are doing here is creating a reverse nat using the
	 * parent's original src addr/port.  We just want this flow to
	 * translate back to the original parent.  We use a dummy tuple
	 * struct to pass the alg nat struct for nat creation.
	 */
	npf_nat_get_orig(pnat, &oaddr, &oport);

	an = sip_create_nat(npf_session_get_vrfid(se), NPF_NAT_REVERSE,
			    false, oaddr, oport, taddr, tport);
	if (!an)
		return -ENOMEM;

	/* Consumes 'an' if successful. */
	rc = npf_alg_session_nat(se, pnat, npc, di, NULL, an);

	if (!rc) {
		sip = apt_tuple_get_client_handle(nt);
		npf_nat_setalg(npf_session_get_nat(se), sip);
	} else
		free(an);

	return rc;
}

/*
 * calculate L4 + L3 checksum deltas.
 */
static void
sip_calculate_checksum_deltas(const void *oaddr, const void *naddr,
			      uint16_t oport, uint16_t nport,
			      uint16_t *l3_delta, uint16_t *l4_delta)
{
	const uint32_t *oip32 = oaddr;
	const uint32_t *nip32 = naddr;

	uint16_t delta = ip_fixup32_cksum(0xffff, *oip32, *nip32);
	*l3_delta = delta ^ 0xffff;

	delta = ip_fixup16_cksum(0xffff, oport, nport);
	*l4_delta = delta ^ 0xffff;
}

/*
 * An RTP or RTCP tuple has been matched.  Called from sip_alg_session_init.
 * Compare with sip_session_nat_alt_cntl.
 */
static int sip_session_nat_media(npf_session_t *se, npf_cache_t *npc,
				 const int di, struct apt_tuple *nt)
{
	struct sip_tuple_data *td;
	struct sip_alg_media *m = NULL;
	struct npf_alg_nat *an;
	npf_session_t *parent;
	uint32_t nat_flags = 0;
	uint32_t alg_flags;
	int rc;

	parent = apt_tuple_get_active_session(nt);
	if (!parent)
		return -ENOENT;

	td = apt_tuple_get_client_data(nt);
	alg_flags = apt_tuple_get_client_flags(nt);

	/*
	 * Create the nat(s).  In SIP's case we always allocate a nat
	 * since we likely allocated consecutive rtp/rtcp ports.
	 *
	 * We have 4 (possible) cases to deal with.  We don't know which
	 * direction the rtp and rtcp flows will originate from and
	 * we will add 4 tuples for those.
	 *
	 * Even though these might be forward flows that match a nat rule,
	 * we already allocated ports during control msg parsing.
	 *
	 * All we do here is create and set the nat struct, unless this
	 * is merely a stateful rule flow set.
	 */
	if (!(alg_flags & SIP_ALG_NAT) || !td)
		return 0;

	/* We may have to reverse the nat */
	if (alg_flags & SIP_ALG_REVERSE)
		nat_flags = NPF_NAT_REVERSE;


	/* Select proper side, either invite or response */
	if (td_is_snat(td))
		m = td->td_mi;
	else if (td_is_dnat(td))
		m = td->td_mr;
	else
		return -EINVAL;

	rc = -ENOMEM;
	vrfid_t vrfid = npf_session_get_vrfid(se);

	switch (alg_flags & SIP_ALG_MASK) {
	case SIP_ALG_RTP_FLOW:
		an = sip_create_nat(vrfid, nat_flags,
				    m->m_rtp_reserved,
				    m->m_rtp_addr, htons(m->m_rtp_port),
				    m->m_trtp_addr, htons(m->m_trtp_port));
		if (an) {
			rc = npf_alg_session_nat(se, npf_alg_parent_nat(parent),
						 npc, di, NULL, an);
			if (!rc)
				m->m_rtp_reserved = false;
			else
				free(an);
		}
		break;
	case SIP_ALG_RTCP_FLOW:
		an = sip_create_nat(vrfid, nat_flags,
				    m->m_rtcp_reserved,
				    m->m_rtcp_addr, htons(m->m_rtcp_port),
				    m->m_trtcp_addr, htons(m->m_trtcp_port));
		if (an) {
			rc = npf_alg_session_nat(se, npf_alg_parent_nat(parent),
						 npc, di, NULL, an);
			if (!rc)
				m->m_rtcp_reserved = false;
			else
				free(an);
		}
		break;
	default:
		return -EINVAL;
	}

	return rc;
}

/*
 * Manage the SIP message.  Used both both NATd and non-NATd pkts.
 *
 * For non-NATd flow, tsr == sr.
 */
int sip_alg_manage_sip(npf_session_t *se, npf_cache_t *npc,
		       struct sip_alg_request *sr,
		       struct sip_alg_request *tsr,
		       npf_nat_t *nat, bool *consumed)
{
	int rc = -EINVAL;

	/*
	 * Handle (thus far) valid requests and responses, all garbage will
	 * result in a drop packet.
	 */
	if (MSG_IS_REQUEST(tsr->sr_sip))
		rc = sip_manage_request(se, npc, sr, tsr, nat, consumed);
	else if (MSG_IS_RESPONSE(tsr->sr_sip))
		rc = sip_manage_response(se, npc, sr, tsr, nat);

	return rc;
}

/*
 * ALG inspect for NATd packets.
 */
int sip_alg_nat(struct npf_session *se, struct npf_cache *npc,
		struct rte_mbuf *nbuf, struct npf_nat *nt,
		const struct npf_alg *alg, int dir)
{
	return sip_alg_translate_packet(se, npc, nt, nbuf,
					(struct npf_alg *)alg, dir);
}

/*
 * Translate reply path *after* IP header has been translated.  Called from
 * the ao_inspect api function.
 *
 * While most SIP implementations set the VIA to match the port/addr of the
 * initiator, the SIP RFC states that reply packets must be routed to the
 * addr/port in the VIA.
 *
 * Newer Cisco phones implement the RFC exactly.  They use a high numbered
 * sport for sending out msgs and expect reply packets on the default SIP port
 * (5060).
 *
 * The situation we have here, according to the RFC is:
 *
 *		a1:p1	-->	a2:p2
 *		a3:p3	<--
 *
 * But this screws up our session handles, which were added to a1:p1 - a2:p2,
 * so we need to do this translation outside of the nat engine to maintain a
 * sane view of session handles (as well as return the reply appropriately.
 *
 * Only do this for UDP.
 */
static void sip_translate_reply_path(npf_session_t *se, int di __unused,
		struct rte_mbuf *nbuf, npf_cache_t *npc)
{
	/*
	 * This function is called from the ALG .inspect callback, and we dont
	 * know if this packet is SIP Request or a SIP Response.  We only want
	 * to rewrite the IP dest for SIP Responses on the reply path.
	 */
	return;


	struct sip_alg_session *ss = npf_alg_session_get_private(se);
	void *n_ptr = npf_iphdr(nbuf);
	struct udphdr *uh = &npc->npc_l4.udp;

	if (!ss)
		return;

	/* Only if this is a response msg */
	if (npc->npc_alg_flags != SIP_NPC_RESPONSE)
		return;

	/* Only udp */
	if (npf_cache_ipproto(npc) != IPPROTO_UDP)
		return;

	/*
	 * Dont rewrite the IP header if we failed to get a return address
	 * from the Via in the Invite, e.g. it may have been a FQDN.
	 */
	if (ss->ss_via_alen == 0)
		return;

	if (uh->dest == ss->ss_via_port)
		return; /* Nothing to do */

	/* Calculate the L3 and L4 checksum delta's */
	uint16_t l3_delta, l4_delta;

	sip_calculate_checksum_deltas(npf_cache_dstip(npc), &ss->ss_via_addr,
				      uh->dest, ss->ss_via_port,
				      &l3_delta, &l4_delta);

	/*
	 * re-write IP and UDP cksums first.
	 */
	if (npf_v4_rwrcksums(npc, nbuf, n_ptr, l3_delta, l4_delta) < 0)
		return;

	/* Now translate */
	if (npf_rwrip(npc, nbuf, n_ptr, PFIL_IN, &ss->ss_via_addr) < 0)
		return;

	/* Now the port */
	npf_rwrport(npc, nbuf, n_ptr, PFIL_IN, ss->ss_via_port);
}

/*
 * Inspect for non-NATd pkts
 */
static void sip_alg_inspect_packet(npf_session_t *se, npf_cache_t *npc,
				   struct rte_mbuf *nbuf, struct npf_alg *sip,
				   int di)
{
	struct sip_alg_request *sr;
	bool consumed = false;

	sr = sip_alg_parse(se, npc, nbuf);
	if (!sr)
		return;

	if (sip_alg_verify(sr)) {
		sip_alg_request_free(sip, sr);
		return;
	}

	sip_init_nat(sr, false, NULL, NULL, 0, 0, di);

	sip_alg_manage_sip(se, npc, sr, sr, NULL, &consumed);

	if (!consumed)
		sip_alg_request_free(sip, sr);
}

/*
 * ALG Inspect of (mostly) non-NATd pkts
 */
void sip_alg_inspect(struct npf_session *se, struct npf_cache *npc,
		     struct rte_mbuf *nbuf, struct npf_alg *alg, int di)
{
	uint32_t flags = npf_alg_session_get_flags(se);

	/* sanity - can only be CNTL flow  */
	if (!(flags & (SIP_ALG_CNTL_FLOW | SIP_ALG_ALT_CNTL_FLOW)))
		return;

	/*
	 * In some curcumstances we want to adjust the packets destination IP
	 * address and port in the IP header of SIP Responses after NAT.
	 */
	if (npf_iscached(npc, NPC_NATTED)) {
		sip_translate_reply_path(se, di, nbuf, npc);
		return;
	}

	/*
	 * Inspect for non-NATd pkts
	 */
	sip_alg_inspect_packet(se, npc, nbuf, alg, di);
}

/*
 * New session has matched a tuple.
 */
int sip_alg_session_init(struct npf_session *se, struct npf_cache *npc,
			 struct apt_tuple *nt, const int di)
{
	npf_session_t *parent;
	uint32_t alg_flags;
	int rc = 0;

	/* Transfer alg_flags from tuple to child session */
	alg_flags = apt_tuple_get_client_flags(nt);
	npf_alg_session_set_flag(se, alg_flags);

	switch (alg_flags & SIP_ALG_MASK) {
	case SIP_ALG_CNTL_FLOW:
		npf_alg_session_set_inspect(se, true);
		rc = sip_alg_private_session_init(se);
		break;

	case SIP_ALG_ALT_CNTL_FLOW:
		parent = apt_tuple_get_active_session(nt);
		if (!parent) {
			rc = -ENOENT;
			break;
		}

		npf_alg_session_set_inspect(se, true);
		npf_alg_session_set_flag(se, SIP_ALG_REVERSE);
		rc = sip_session_nat_alt_cntl(se, npc, di, nt, parent);

		if (!rc)
			npf_session_link_child(parent, se);
		break;

	case SIP_ALG_RTP_FLOW:
		parent = apt_tuple_get_active_session(nt);
		if (!parent) {
			rc = -ENOENT;
			break;
		}

		rc = sip_session_nat_media(se, npc, di, nt);
		if (!rc) {
			struct sip_tuple_data *td;

			td = apt_tuple_get_client_data(nt);
			sip_alg_create_rtcp_tuples(se, npc, td);

			npf_session_link_child(parent, se);
		}
		break;

	case SIP_ALG_RTCP_FLOW:
		parent = apt_tuple_get_active_session(nt);
		if (!parent) {
			rc = -ENOENT;
			break;
		}

		rc = sip_session_nat_media(se, npc, di, nt);
		if (!rc)
			npf_session_link_child(parent, se);
		break;
	default:
		rc = -EINVAL;
		break;
	}

	return rc;
}

/*
 * An SIP alg session has been expired.
 *
 * Expire any requests in the hash table that are associated with this
 * session.  We know this from the list of call IDs stored in the session
 * context private data.
 */
void sip_alg_session_expire(struct npf_session *se)
{
	if (npf_alg_session_test_flag(se, SIP_ALG_CNTL_FLOW))
		sip_expire_session_request(se);
}

/*
 * An SIP alg session is being destroyed.
 */
void sip_alg_session_destroy(struct npf_session *se)
{
	if (npf_alg_session_test_flag(se, SIP_ALG_CNTL_FLOW)) {
		sip_flush_session_request(se);
		sip_alg_private_session_free(se);
	}
}

bool sip_alg_cntl_session(struct npf_session_alg *sa)
{
	return (sa->sa_flags & (SIP_ALG_CNTL_FLOW |
				SIP_ALG_ALT_CNTL_FLOW)) != 0;
}

/*
 * Notification that a SIP tuple has been deleted
 */
void sip_alg_apt_delete(struct apt_tuple *nt)
{
	sip_tuple_data_detach(nt);
}

/* sip_alg_config() - Config routine for sip */
static int sip_alg_config(struct npf_alg *sip, int op, int argc,
			char * const argv[])
{
	struct npf_alg_config_item ci = {
		.ci_flags = NPF_TUPLE_KEEP | NPF_TUPLE_MATCH_PROTO_PORT,
		.ci_alg_flags = SIP_ALG_CNTL_FLOW
	};
	int rc;
	int i;

	/* Only ports, skip */
	if (strcmp(argv[0], "port") != 0)
		return 0;
	argc--; argv++;

	for (i = 0; i < argc; i++) {
		ci.ci_datum = npf_port_from_str(argv[i]);
		if (!ci.ci_datum)
			continue;

		/*
		 * Treat ports are a protocol pair
		 * (Really should be separate CLI)
		 */
		ci.ci_proto = IPPROTO_UDP;
		rc = npf_alg_manage_config_item(sip, &sip->na_configs[0],
				op, &ci);
		if (rc)
			return rc;

		ci.ci_proto = IPPROTO_TCP;
		rc = npf_alg_manage_config_item(sip, &sip->na_configs[0],
				op, &ci);
		if (rc) {
			/* unwind if possible */
			ci.ci_proto = IPPROTO_UDP;
			npf_alg_manage_config_item(sip, &sip->na_configs[0],
				NPF_ALG_CONFIG_DELETE, &ci);
			return rc;
		}
	}

	return 0;
}

/*
 * ALG periodic hook
 */
void sip_alg_periodic(struct npf_alg *sip)
{
	sip_ht_gc(sip);
}

static void
sip_alg_session_media_json(json_writer_t *json, struct sip_alg_media *m)
{
	char buf[INET6_ADDRSTRLEN];
	int af;

	jsonw_start_object(json);

	if (m->m_proto == sdp_proto_udp)
		jsonw_string_field(json, "proto", "udp");
	else if (m->m_proto == sdp_proto_rtp)
		jsonw_string_field(json, "proto", "rtp");
	else
		jsonw_string_field(json, "proto", "unknown");

	if (m->m_rtp_alen) {
		af = (m->m_rtp_alen == 4) ? AF_INET : AF_INET6;
		inet_ntop(af, &m->m_rtp_addr, buf, sizeof(buf));
		jsonw_string_field(json, "rtp_addr", buf);
	}
	if (m->m_rtp_port)
		jsonw_uint_field(json, "rtp_port", m->m_rtp_port);

	if (m->m_rtcp_alen) {
		af = (m->m_rtcp_alen == 4) ? AF_INET : AF_INET6;
		inet_ntop(af, &m->m_rtcp_addr, buf, sizeof(buf));
		jsonw_string_field(json, "rtcp_addr", buf);
	}
	if (m->m_rtcp_port)
		jsonw_uint_field(json, "rtcp_port", m->m_rtcp_port);

	if (m->m_trtp_alen) {
		af = (m->m_trtp_alen == 4) ? AF_INET : AF_INET6;
		inet_ntop(af, &m->m_trtp_addr, buf, sizeof(buf));
		jsonw_string_field(json, "trtp_addr", buf);
	}
	if (m->m_trtp_port)
		jsonw_uint_field(json, "trtp_port", m->m_trtp_port);

	if (m->m_trtcp_alen) {
		af = (m->m_trtcp_alen == 4) ? AF_INET : AF_INET6;
		inet_ntop(af, &m->m_trtcp_addr, buf, sizeof(buf));
		jsonw_string_field(json, "trtcp_addr", buf);
	}
	if (m->m_trtcp_port)
		jsonw_uint_field(json, "trtcp_port", m->m_trtcp_port);

	jsonw_end_object(json);
}

static void
sip_alg_session_callid_json(json_writer_t *json, npf_session_t *se,
			    osip_call_id_t *call_id)
{
	char *number, *host;
	struct npf_alg *sip = npf_alg_session_get_alg(se);
	struct sip_alg_request *sr;
	struct sip_alg_media *m, *tmp;
	uint32_t if_idx = npf_session_get_if_index(se);
	char buf[100];

	number = osip_call_id_get_number(call_id);
	host = osip_call_id_get_host(call_id);

	if (!number)
		return;

	jsonw_start_object(json);

	if (!host)
		snprintf(buf, sizeof(buf), "%s", number);
	else
		snprintf(buf, sizeof(buf), "%s@%s", number, host);
	jsonw_string_field(json, "number", buf);

	sr = sip_request_lookup_by_call_id(sip, if_idx, call_id);
	if (!sr) {
		jsonw_end_object(json);
		return;
	}

	jsonw_name(json, "media");
	jsonw_start_array(json);

	cds_list_for_each_entry_safe(m, tmp, &sr->sr_media_list_head, m_node)
		sip_alg_session_media_json(json, m);

	jsonw_end_array(json);
	jsonw_end_object(json);
}

void sip_alg_session_json(struct json_writer *json, struct npf_session *se)
{
	struct sip_alg_session *ss;
	char buf[INET6_ADDRSTRLEN];

	if (!json || !se)
		return;

	ss = npf_alg_session_get_private(se);
	if (!ss)
		return;

	jsonw_name(json, "sip");
	jsonw_start_object(json);

	if (ss->ss_via_alen)
		jsonw_string_field(
			json, "via_addr",
			inet_ntop(ss->ss_via_alen == 4 ? AF_INET : AF_INET6,
				  &ss->ss_via_addr,
				  buf, sizeof(buf)));

	if (ss->ss_via_port)
		jsonw_uint_field(json, "via_port", ntohs(ss->ss_via_port));

	if (ss->ss_call_id_count > 0) {
		int i;

		jsonw_name(json, "callids");
		jsonw_start_array(json);

		for (i = 0; i < ss->ss_call_id_count; i++)
			sip_alg_session_callid_json(json, se,
						    ss->ss_call_ids[i]);

		jsonw_end_array(json);
	}

	jsonw_end_object(json);
}

/* alg struct */
static const struct npf_alg_ops sip_ops = {
	.config		= sip_alg_config,
};

static const struct npf_alg_config_item sip_ports[] = {
	{ IPPROTO_TCP, (NPF_TUPLE_KEEP | NPF_TUPLE_MATCH_PROTO_PORT),
		SIP_ALG_CNTL_FLOW, SIP_DEFAULT_PORT },
	{ IPPROTO_UDP, (NPF_TUPLE_KEEP | NPF_TUPLE_MATCH_PROTO_PORT),
		SIP_ALG_CNTL_FLOW, SIP_DEFAULT_PORT },
};

struct npf_alg *npf_alg_sip_create_instance(struct npf_alg_instance *ai)
{
	struct npf_alg *sip;
	struct sip_private *sp = NULL;
	int rc = -ENOMEM;

	sip = npf_alg_create_alg(ai, NPF_ALG_ID_SIP);
	if (!sip)
		goto bad;

	sip->na_ops = &sip_ops;

	/* setup default config */
	sip->na_num_configs = 1;
	sip->na_configs[0].ac_items = sip_ports;
	sip->na_configs[0].ac_item_cnt = ARRAY_SIZE(sip_ports);
	sip->na_configs[0].ac_handler = npf_alg_port_handler;

	sp = zmalloc_aligned(sizeof(struct sip_private));
	if (!sp)
		goto bad;

	rc = sip_ht_create(sp);
	if (rc < 0)
		goto bad;

	rte_spinlock_init(&sp->sp_media_lock);
	CDS_INIT_LIST_HEAD(&sp->sp_dead_media);

	sip->na_private = sp;

	rc = npf_alg_register(sip);
	if (rc)
		goto bad;

	/* Take reference on an alg application instance */
	npf_alg_get(sip);

	return sip;

bad:
	if (net_ratelimit())
		RTE_LOG(ERR, FIREWALL, "ALG: SIP instance failed: %d\n", rc);

	if (sp && sp->sp_ht)
		cds_lfht_destroy(sp->sp_ht, NULL);
	free(sp);
	free(sip);
	return NULL;
}

/*
 * Destroy - we are guaranteed no access and a rcu quiesce period has
 * passed.
 */
void npf_alg_sip_destroy_instance(struct npf_alg *sip)
{
	if (!sip)
		return;


	/* Expire or delete tuples */
	alg_apt_instance_client_destroy(sip->na_ai->ai_apt, sip);

	sip_destroy_ht(sip);

	free(sip->na_private);
	sip->na_private = NULL;

	sip->na_enabled = false;
	sip->na_ai = NULL;

	/* Release reference on an alg application instance */
	npf_alg_put(sip);
}

/*
 * Constructor for one-time libosip initialization
 */
static void npf_alg_sip_init(void) __attribute__ ((__constructor__));

static void npf_alg_sip_init(void)
{
	osip_init(&sip_osip);
}
