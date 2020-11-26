/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * SIP parse.
 *
 * sip_alg_parse will parse a SIP packet (Invite or Response) looking for an
 * SDP message contained in it.  If found, a sip_alg_request is allocated and
 * returned.
 *
 * sip_alg_manage_media will parse the SDP "c=" and "m=" strings, and (if not
 * in 'inspect' path) translate the "c=" address.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <rte_atomic.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <urcu.h>

#include "vrf.h"
#include "util.h"
#include "vplane_log.h"

#include "npf/npf.h"
#include "npf/alg/alg.h"
#include "npf/npf_cache.h"
#include "npf/npf_nat.h"
#include "npf/npf_session.h"


/*
 *  Max media connections per INVITE.
 */
#define SDP_MAX_MEDIA 8


/*
 * sip_alg_set_dnat_rtcp_media() - Init/finalize media addr/ports
 */
static void sip_alg_dnat_rtcp_media(struct sip_alg_media *m, npf_nat_t *nat)
{
	in_port_t tmp;
	bool do_rtcp = false;

	if (!IN6_IS_ADDR_UNSPECIFIED(&m->m_rtcp_addr) &&
		memcmp(&m->m_rtp_addr, &m->m_rtcp_addr, m->m_rtp_alen) == 0)
		do_rtcp = true;

	/* Reset to original address */
	npf_nat_get_orig(nat, &m->m_rtp_addr, &tmp);

	/*
	 * If an rtcp attribute was sent, use it
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(&m->m_rtcp_addr)) {
		m->m_rtcp_addr = m->m_rtp_addr;
		m->m_rtcp_port = m->m_rtp_port + 1;
		m->m_rtcp_alen = m->m_rtp_alen;
		m->m_trtcp_addr = m->m_trtp_addr;
		m->m_trtcp_port = m->m_rtcp_port;
		m->m_trtcp_alen = m->m_rtcp_alen;
	} else {
		m->m_trtcp_addr = m->m_rtcp_addr;
		m->m_trtcp_port = m->m_rtcp_port;
		m->m_trtcp_alen = m->m_rtcp_alen;
		if (do_rtcp)
			m->m_rtcp_addr = m->m_rtp_addr;
	}
}

/*
 * sip_alg_set_rtcp_media() - Init/finalize media addr/ports
 */
static void sip_alg_set_rtcp_media(struct sip_alg_media *m)
{
	/*
	 * If an rtcp attribute was sent, use it
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(&m->m_rtcp_addr)) {
		m->m_rtcp_addr = m->m_rtp_addr;
		m->m_rtcp_port = m->m_rtp_port + 1;
		m->m_rtcp_alen = m->m_rtp_alen;
	}

	m->m_trtcp_addr = m->m_rtcp_addr;
	m->m_trtcp_port = m->m_rtcp_port;
	m->m_trtcp_alen = m->m_rtcp_alen;
}

/*
 * Parse the sdp session (global) media address
 */
static int
sip_alg_parse_session_media_addr(struct sip_alg_request *sr,
				 npf_addr_t *addr, uint8_t *alen)
{
	sdp_connection_t *c;
	int rc = -1;

	c = sdp_message_connection_get(sr->sr_sdp, -1, 0);
	if (!c)
		return 0;

	sip_addr_from_str(c->c_addr, addr, alen);
	if (*alen)
		rc = 0;

	return rc;
}

/*
 * sip_alg_sdp_get_media_proto()
 */
static int sip_alg_sdp_get_media_proto(struct sip_alg_request *sr, int pos)
{
	char *proto = sdp_message_m_proto_get(sr->sr_sdp, pos);

	if (!proto)
		return -1;

	if (strstr(proto, "UDP"))
		return sdp_proto_udp;
	else if (strstr(proto, "RTP"))
		return sdp_proto_rtp;
	return sdp_proto_unknown;
}

/*
 * sip_alg_sdp_update_origin() - Update the "o=" field.
 */
static int sip_alg_sdp_update_origin(struct sip_alg_request *sr)
{
	char *nettype = sdp_message_o_nettype_get(sr->sr_sdp);
	char *addrtype = sdp_message_o_addrtype_get(sr->sr_sdp);

	if (!nettype || strcmp(nettype, "IN") != 0)
		return -EINVAL;

	if (addrtype && !strcmp(addrtype, "IP6"))
		return 0;  /* Ignore IPv6 */

	if (!addrtype || strcmp(addrtype, "IP4") != 0)
		return -EINVAL;  /* Unknown/unsupported */

	if (!sip_translate_addr_reqd(sr->sr_sdp->o_addr, sip_oaddr(sr)))
		return 0; /* Nothing to do */

	/* <sigh> no api */
	osip_free(sr->sr_sdp->o_addr);
	sr->sr_sdp->o_addr = osip_strdup(sip_taddr(sr));
	if (!sr->sr_sdp->o_addr)
		return -ENOMEM;
	return 0;
}

/*
 * sip_alg_get_sdp_attribute()
 */
static sdp_attribute_t *sip_alg_get_sdp_attribute(struct sip_alg_request *sr,
						int pos, const char *name)
{
	int i = 0;
	sdp_attribute_t *a;

	while ((a = sdp_message_attribute_get(sr->sr_sdp, pos, i)) != NULL) {
		if (!strncmp(a->a_att_field, name, strlen(name)))
			return a;
		i++;
	}
	return NULL;
}

/*
 * sip_parse_rtcp() - Get port and (optional) addr from an rtcp attribute.
 *
 * Example RTCP SDP attributes:
 *   a=rtcp:53020
 *   a=rtcp:53020 IN IP4 126.16.64.4
 *   a=rtcp:53020 IN IP6 2001:2345:6789:ABCD:EF01:2345:6789:ABCD
 *
 * The "rtcp:" part is stripped off sip_alg_get_sdp_attribute, and the
 * attribute value passed in here is of the form "53020 IN IP4 126.16.64.4".
 * Note that only the port number is mandatory.
 */
static int sip_parse_rtcp(const char *value,
		in_port_t *port, npf_addr_t *addr, uint8_t *alen)
{
	char *cport = NULL;
	char *cnettype = NULL;
	char *caddrtype = NULL;
	char *caddr = NULL;
	int i;
	int rc = 0;

	i = sscanf(value, "%5ms %2ms %3ms %46ms",
			&cport, &cnettype, &caddrtype, &caddr);
	if (i > 0) {
		*port = npf_port_from_str(cport);
		/* Address is optional, verify if present */
		if (*port && (i == 4)) {
			sip_addr_from_str(caddr, addr, alen);
			if (!*alen)
				rc = -EINVAL;
		}
	}
	free(cport);
	free(cnettype);
	free(caddrtype);
	free(caddr);

	return rc;
}

/*
 * sip_alg_sdp_get_rtcp_attribute() - Get the rtcp attribute params if present.
 */
static int sip_alg_sdp_get_rtcp_attribute(struct sip_alg_request *sr,
					struct sip_alg_media *m, int pos)
{
	sdp_attribute_t *a;
	int rc = 0;

	a = sip_alg_get_sdp_attribute(sr, pos, "rtcp");
	if (a) {
		rc = sip_parse_rtcp(a->a_att_value, &m->m_rtcp_port,
				&m->m_rtcp_addr, &m->m_rtcp_alen);
		if (rc)
			return rc;
	}

	/*
	 * Now default for addr if not set.
	 */
	if (m->m_rtcp_port && IN6_IS_ADDR_UNSPECIFIED(&m->m_rtcp_addr)) {
		m->m_rtcp_addr = m->m_rtp_addr;
		m->m_rtcp_alen = m->m_rtp_alen;
	}

	return rc;
}

/*
 * sip_alg_set_rtcp_attribute() - Update "rtcp" attribute if present
 */
int sip_alg_sdp_set_rtcp_attribute(struct sip_alg_request *sr,
				   int pos, npf_addr_t *taddr, uint8_t alen,
				   in_port_t tport)
{
	sdp_attribute_t *a;
	int rc = 0; /* Not an error if ENOENT */

	/* Only if the rtcp port exists */
	if (!tport)
		return 0;

	a = sip_alg_get_sdp_attribute(sr, pos, "rtcp");
	if (a) {
		char *cport = NULL;
		char *cnettype = NULL;
		char *caddrtype = NULL;
		char *caddr = NULL;
		int i;
		char value[70];
		char *naddr;

		naddr = sip_addr_to_str(taddr, alen);
		if (!naddr)
			return -ENOMEM;

		i = sscanf(a->a_att_value, "%5ms %2ms %3ms %46ms",
				&cport, &cnettype, &caddrtype, &caddr);

		if (i <= 0) {
			osip_free(naddr);
			return -EINVAL;
		}

		if (i == 1)
			rc = snprintf(value, sizeof(value), "%hu", tport);
		else if (i == 4)
			rc = snprintf(value, sizeof(value), "%hu %s %s %s",
					tport, cnettype, caddrtype, naddr);
		else
			rc = -EINVAL;

		free(cport);
		free(cnettype);
		free(caddrtype);
		free(caddr);
		osip_free(naddr);

		if (rc > 0 && (uint)rc < sizeof(value)) {
			osip_free(a->a_att_value);
			a->a_att_value = osip_strdup(value);
			rc = 0;
		} else {
			rc = -ENOMEM;
		}
	}
	return rc;
}

/*
 * sip_alg_parse_media_addr()
 */
static int sip_alg_parse_media_addr(struct sip_alg_media *m,
		struct sip_alg_request *sr, int pos)
{
	sdp_connection_t *c;
	int rc = -1;

	c = sdp_message_connection_get(sr->sr_sdp, pos, 0);
	if (c) {
		sip_addr_from_str(c->c_addr, &m->m_rtp_addr, &m->m_rtp_alen);
		if (m->m_rtp_alen)
			rc = 0;
	}
	return rc;
}

static int sip_alg_parse_media_ports(struct sip_alg_media *m,
		struct sip_alg_request *sr, int pos)
{
	char *cport = sdp_message_m_port_get(sr->sr_sdp, pos);
	int rc = 0;

	/* Must have a port in the media */
	if (!cport)
		return -EINVAL;

	switch (m->m_proto) {
	case sdp_proto_udp:
		m->m_rtp_port = npf_port_from_str(cport);
		if (!m->m_rtp_port)
			rc = -EINVAL;
		break;
	case sdp_proto_rtp:
		m->m_rtp_port = npf_port_from_str(cport);
		if (!m->m_rtp_port) {
			rc = -EINVAL;
			break;
		}
		/* Default rtcp port for inspect */
		if (sip_is_inspect(sr))
			m->m_rtcp_port = m->m_rtp_port+1;
		/* Do we have an attribute rtcp port? */
		rc = sip_alg_sdp_get_rtcp_attribute(sr, m, pos);
		break;
	default:
		rc = -EINVAL;
		break;
	}

	return rc;
}

/*
 * sip_alg_reserve_ports()
 */
static int sip_alg_reserve_ports(npf_session_t *se,
		struct sip_alg_media *m, npf_nat_t *ns)
{
	int n = 1;
	bool start_even = false;
	in_port_t port;
	int rc;
	npf_natpolicy_t *np = npf_nat_get_policy(ns);
	uint32_t nat_flags = NPF_NAT_MAP_PORT;
	npf_rule_t *rl = npf_nat_get_rule(ns);
	vrfid_t vrfid = npf_session_get_vrfid(se);

	/*
	 * If we do not have an rtcp attribute, then we need
	 * to allocate 2 consecutive ports, starting on an even
	 * boundary.  Otherwise, one port will do.
	 */
	if (m->m_proto == sdp_proto_rtp &&
			IN6_IS_ADDR_UNSPECIFIED(&m->m_rtcp_addr)) {
		start_even = true;
		n = 2;
	}

	port = htons(m->m_trtp_port);
	rc = npf_alg_reserve_translations(se, n, start_even, m->m_rtp_alen,
			&m->m_trtp_addr, &port);
	if (rc)
		return rc;
	m->m_trtp_port = ntohs(port);
	m->m_ip_prot = npf_session_get_proto(se);
	m->m_rtp_reserved = true;

	/* If the proto is not rtp, we are done. */
	if (m->m_proto != sdp_proto_rtp)
		return rc;

	/*
	 * If we didn't have an rtcp attribute, then
	 * default the rtcp members use the allocated port
	 *
	 * Otherwise, we have an rtcp attribute with an addr,
	 * (which may be the same as the rtp addr)
	 * and we need to get a distinct mapping for that
	 * addr/port pair
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(&m->m_rtcp_addr)) {
		m->m_rtcp_addr = m->m_rtp_addr;
		m->m_rtcp_port = m->m_rtp_port+1;
		m->m_rtcp_alen = m->m_rtp_alen;

		m->m_trtcp_port = ntohs(port) + 1;
		m->m_trtcp_addr = m->m_trtp_addr;
		m->m_trtcp_alen = m->m_trtp_alen;
		m->m_rtcp_reserved = true;
	} else {
		/*
		 * If the rtcp addr is the same as the rtp addr,
		 * then we need to allocate a port.  Otherwise,
		 * this is a remote host.
		 */
		if (!memcmp(&m->m_rtcp_addr, &m->m_rtp_addr, m->m_rtp_alen)) {
			m->m_trtcp_addr = m->m_trtp_addr;
			port = htons(m->m_rtcp_port);
			rc = npf_nat_alloc_map(np, rl, nat_flags, m->m_ip_prot,
					vrfid, &m->m_trtcp_addr, &port, 1);
			if (rc)
				return rc;
			m->m_trtcp_port = ntohs(port);
			m->m_trtcp_alen = m->m_rtcp_alen;
			m->m_rtcp_reserved = true;
		} else {
			m->m_trtcp_addr = m->m_rtcp_addr;
			m->m_trtcp_port = m->m_rtcp_port;
			m->m_trtcp_alen = m->m_rtcp_alen;
		}
	}

	return rc;
}

/*
 * sip_media_translations() - Get media translations if needed.
 */
static int sip_media_translations(npf_session_t *se,
		struct sip_alg_media *m, struct sip_alg_request *sr,
		npf_nat_t *nat)
{
	int rc = 0;

	/* Set defaults for translation addrs/ports.  */
	m->m_trtp_port = m->m_rtp_port;
	m->m_trtp_addr = m->m_rtp_addr;
	m->m_trtp_alen = m->m_rtp_alen;

	 /* If IPv6 or inspection */
	if (m->m_rtp_alen > 4 || sip_is_inspect(sr)) {
		sip_alg_set_rtcp_media(m);
		return rc;
	}

	/*
	 * Handle both INVITE and OK's for both SNAT and DNAT.
	 * Only SNAT must reserve ports.
	 */
	switch (sip_nat_type(sr)) {
	case sip_nat_snat:
		if (sip_forw(sr))
			rc = sip_alg_reserve_ports(se, m, nat);
		else
			sip_alg_set_rtcp_media(m);
		break;
	case sip_nat_dnat:
		if (sip_forw(sr))
			sip_alg_set_rtcp_media(m);
		else
			sip_alg_dnat_rtcp_media(m, nat);
		break;
	default:
		return -EINVAL;
	}
	return rc;
}

static bool sip_do_translate(const struct sip_alg_request *sr)
{
	switch (sip_nat_type(sr)) {
	case sip_nat_snat:
		if (sip_forw(sr))
			return true;
		break;
	case sip_nat_dnat:
		if (!sip_forw(sr))
			return true;
		break;
	default:	/* Hush up gcc */
		break;
	}

	return false;
}

/*
 * Parse the SDP "c=" and "m=" strings, and (if not in 'inspect' path)
 * translate the "c=" address.
 */
int sip_alg_manage_media(npf_session_t *se, npf_nat_t *nat,
			 struct sip_alg_request *sr)
{
	int rc;
	int pos;
	struct sip_alg_media *m;
	enum sdp_proto m_prot;

	/*
	 * Update session connection
	 */
	if (sip_is_snat(sr)) {
		rc = sip_alg_sdp_update_origin(sr);
		if (rc)
			return rc;
	}

	npf_addr_t s_rtp_addr;
	uint8_t	s_rtp_alen = 0;

	sip_alg_parse_session_media_addr(sr, &s_rtp_addr, &s_rtp_alen);

	for (pos = 0; !sdp_message_endof_media(sr->sr_sdp, pos) &&
					pos < SDP_MAX_MEDIA; pos++) {

		m_prot = sip_alg_sdp_get_media_proto(sr, pos);

		rc = -ENOMEM;
		m = sip_media_alloc(se, sr, m_prot);
		if (!m)
			goto bad;

		rc = sip_alg_parse_media_addr(m, sr, pos);
		if (rc) {
			/* No media addr. Use SDP session addr */
			if (!s_rtp_alen)
				goto bad;
			m->m_rtp_addr = s_rtp_addr;
			m->m_rtp_alen = s_rtp_alen;
		}

		rc = sip_alg_parse_media_ports(m, sr, pos);
		if (rc)
			goto bad;

		rc = sip_media_translations(se, m, sr, nat);
		if (rc)
			goto bad;

		if (sip_do_translate(sr)) {
			rc = sip_alg_translate_media(sr, m, pos);
			if (rc)
				goto bad;
		}

		cds_list_add_tail(&m->m_node, &sr->sr_media_list_head);
	}

	/*
	 * Translate the session connection address
	 */
	if (s_rtp_alen && sip_do_translate(sr))
		sip_alg_update_session_media(sr);

	return 0;
bad:
	sip_media_free(m);
	return rc;
}

/*
 *  sip_alg_body_is_sdp() - Do we have an SDP message?
 */
static bool sip_alg_body_is_sdp(struct sip_alg_request *sr)
{
	osip_content_type_t *ct;

	ct = osip_message_get_content_type(sr->sr_sip);
	if (!ct)
		return false;

	if (ct->type && !strstr(ct->type, "application"))
		return false;

	if (ct->subtype && !strstr(ct->subtype, "sdp"))
		return false;

	return true;
}

/*
 * sip_alg_get_sdp()
 */
static int sip_alg_get_sdp(struct sip_alg_request *sr)
{
	osip_body_t *sdp_body;
	sdp_message_t *sdp;
	int rc;

	if (!sip_alg_body_is_sdp(sr))
		return 0;

	rc = osip_message_get_body(sr->sr_sip, 0, &sdp_body);
	if (rc >= 0) {
		rc = sdp_message_init(&sdp);
		if (rc < 0)
			return rc;
		rc = sdp_message_parse(sdp, sdp_body->body);
		if (!rc)
			sr->sr_sdp = sdp;
		else
			sdp_message_free(sdp);
	}

	return rc;
}

/*
 * Parse a sip packet using the osip library.  We are only interested in
 * packets containing an SDP message. Returns a sip_alg_request structure is
 * successful.
 */
struct sip_alg_request *sip_alg_parse(const struct npf_alg *sip,
				      npf_cache_t *npc, uint32_t if_idx,
				      struct rte_mbuf *nbuf)
{
	struct sip_alg_request *sr = NULL;
	uint16_t plen;
	char payload[SIP_MESSAGE_MAX_LENGTH + 1];
	int rc;

	plen = npf_payload_fetch(npc, nbuf, payload,
			SIP_MSG_MIN_LENGTH, SIP_MESSAGE_MAX_LENGTH);
	if (!plen)
		return NULL;

	/* Make the payload a string */
	payload[plen] = '\0';

	sr = sip_alg_request_alloc(true, if_idx);
	if (!sr)
		return NULL;

	rc = osip_message_parse(sr->sr_sip, payload, plen);
	if (rc != 0)
		goto bad;

	/* Get the sdp portion if present */
	rc = sip_alg_get_sdp(sr);
	if (rc)
		goto bad;

	return sr;

bad:
	sip_alg_request_free(sip, sr);
	return NULL;
}

