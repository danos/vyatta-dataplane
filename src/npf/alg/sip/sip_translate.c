/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * SIP alg translate
 *
 * sip_alg_translate_packet is called from the ao_nat api function to
 * translate a SIP packet.
 *
 * sip_alg_translate_media translates the media in the SDP "m=" strings.
 *
 * sip_alg_update_session_media translates the media address in the SDP "c="
 * string
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
#include "npf/alg/alg_session.h"
#include "npf/npf_cache.h"
#include "npf/npf_nat.h"
#include "npf/npf_session.h"

/*
 * Only translate a port if it is present in the url, and is different from
 * tport
 */
static inline bool sip_translate_port_reqd(const char *port, const char *tport)
{
	if (!port || !tport)
		return false;

	if (strcmp(port, tport) == 0)
		return false;

	return true;
}

static int sip_alg_translate_media_connect(sdp_connection_t *c,
				char *addr)
{
	/*
	 * Performs basic sanity as well.
	 *
	 * If we do not have a translation address, we are not
	 * translating this packet.  Do nothing.
	 *
	 * Do not translate IPv6
	 */
	if (!addr)
		return 0;

	if (strcmp(c->c_nettype, "IN") != 0)
		return -EINVAL;

	if (!strcmp(c->c_addrtype, "IP6"))
		return 0;

	if (strcmp(c->c_addrtype, "IP4") != 0)
		return -EINVAL;

	osip_free(c->c_addr);
	c->c_addr = addr;
	return 0;
}

static int sip_alg_translate_media_port(struct sip_alg_request *sr,
				int pos, in_port_t port)
{
	char *cport;

	cport = sip_port_to_str(port);
	if (!cport)
		return -ENOMEM;

	if (sdp_message_m_port_set(sr->sr_sdp, pos, cport)) {
		osip_free(cport);
		return -EINVAL;
	}
	return 0;
}

static int sip_alg_update_media(struct sip_alg_request *sr,
		int pos, npf_addr_t *taddr, uint8_t alen, in_port_t port)
{
	sdp_connection_t *c;
	int rc = 0;
	char *addr;

	/*
	 * Update the connection ("c=") and media ("m=") with
	 * the translation address and port.
	 */
	c = sdp_message_connection_get(sr->sr_sdp, pos, 0);

	if (c) {
		if (!sip_translate_addr_reqd(c->c_addr, sip_oaddr(sr)))
			return 0; /* Nothing to do */

		addr = sip_addr_to_str(taddr, alen);
		if (!addr)
			return -EINVAL;

		rc = sip_alg_translate_media_connect(c, addr);
		if (rc) {
			osip_free(addr);
			return rc;
		}
	} else {
		/*
		 * There is no media connection address.  Only translate media
		 * port if session connection address matches the NAT target
		 * address.
		 */
		c = sdp_message_connection_get(sr->sr_sdp, -1, 0);

		if (!c || !sip_translate_addr_reqd(c->c_addr, sip_oaddr(sr)))
			return 0; /* Nothing to do */
	}

	return sip_alg_translate_media_port(sr, pos, port);
}

/*
 * Translates the media in the SDP "m=" strings
 */
int sip_alg_translate_media(struct sip_alg_request *sr,
			    struct sip_alg_media *m, int pos)
{
	int rc;

	/*
	 * N.B.: If this is dnat, then this 'm' is generated off
	 * a response from the server.  This means that we received the
	 * dnat translation port.  IOW, we need to do a 'reverse' translation
	 * on this msg.
	 *
	 * So make sure we re-write the packet with the correct port.
	 */
	if (sip_is_snat(sr))
		rc = sip_alg_update_media(sr, pos, &m->m_trtp_addr,
				m->m_trtp_alen, m->m_trtp_port);
	else
		rc = sip_alg_update_media(sr, pos, &m->m_rtp_addr,
				m->m_rtp_alen, m->m_rtp_port);
	if (!rc) {
		if (sip_is_snat(sr))
			rc =  sip_alg_sdp_set_rtcp_attribute(sr, pos,
					&m->m_trtcp_addr, m->m_trtcp_alen,
					m->m_trtcp_port);
		else
			rc =  sip_alg_sdp_set_rtcp_attribute(sr, pos,
					&m->m_rtcp_addr, m->m_rtcp_alen,
					m->m_rtcp_port);
	}
	return rc;
}

/*
 * Translates the media address in the SDP "c=" string
 */
void sip_alg_update_session_media(struct sip_alg_request *sr)
{
	sdp_connection_t *c;
	char *addr;

	c = sdp_message_connection_get(sr->sr_sdp, -1, 0);
	if (!c)
		return;

	if (!sip_translate_addr_reqd(c->c_addr, sip_oaddr(sr)))
		return;

	addr = osip_strdup(sip_taddr(sr));
	if (addr)
		sip_alg_translate_media_connect(c, addr);
}

/*
 * sip_alg_translate_url()
 */
static int sip_alg_translate_url(osip_uri_t *u, const char *oaddr,
				  const char *taddr, const char *port)
{
	if (!u)
		return 0;

	if (!sip_translate_addr_reqd(u->host, oaddr))
		return 0;

	osip_free(u->host);
	u->host = osip_strdup(taddr);

	/* translate the port if present */
	if (sip_translate_port_reqd(u->port, port)) {
		osip_free(u->port);
		u->port = osip_strdup(port);
	}
	return 0;
}

/*
 * sip_alg_translate_from - Translate a From header
 */
static int sip_alg_translate_from(struct sip_alg_request *tsr,
				  const char *taddr, const char *tport)
{
	osip_uri_t *from;
	int rc = -1;

	from = osip_from_get_url(osip_message_get_from(tsr->sr_sip));
	if (from)
		rc = sip_alg_translate_url(from, sip_oaddr(tsr), taddr, tport);
	return rc;
}

/*
 * sip_alg_translate_to - Translate a To header
 */
static int sip_alg_translate_to(struct sip_alg_request *tsr,
				const char *taddr, const char *tport)
{
	osip_uri_t *to;
	int rc = -1;

	to = osip_from_get_url(osip_message_get_to(tsr->sr_sip));
	if (to)
		rc = sip_alg_translate_url(to, sip_oaddr(tsr), taddr, tport);
	return rc;
}

/*
 * sip_alg_translate_call_id - Translate a Call-Id header
 */
static int sip_alg_translate_call_id(struct sip_alg_request *tsr,
				     const char *addr)
{
	osip_call_id_t *cid = osip_message_get_call_id(tsr->sr_sip);
	char *p;

	if (cid) {
		p = osip_call_id_get_host(cid);
		if (sip_translate_addr_reqd(p, sip_oaddr(tsr))) {
			osip_free(p);
			osip_call_id_set_host(cid, osip_strdup(addr));
		}
	}
	return 0;
}

/*
 * sip_alg_translate_user_agent() - Translate User-Agent header
 */
static int sip_alg_translate_user_agent(struct sip_alg_request *tsr,
					const char *taddr)
{
	osip_header_t *h;
	int rc = 0;
	int n;
	char *p;

	osip_message_get_user_agent(tsr->sr_sip, 0, &h);
	if (h) {
		/*
		 * This can contain anything.  But we only need to
		 * replace the original address, if present, with
		 * the taddr
		 */
		p = strstr(h->hvalue, sip_oaddr(tsr));
		if (!p)
			return 0; /* Nothing to do */

		/* Ensure enough space */
		rc = strlen(h->hvalue) + strlen(taddr);

		char buf[rc + 1]; /* avoid 0 bounds VLA */

		n = p - h->hvalue;
		memset(buf, '\0', sizeof(buf));
		memcpy(buf, h->hvalue, n);
		strcat(buf, taddr);
		n += strlen(sip_oaddr(tsr));
		strcat(buf, &h->hvalue[n]);
		p = osip_strdup(buf);
		if (!p)
			return -ENOMEM;
		osip_free(h->hvalue);
		h->hvalue = p;
		rc = 0;
	}
	return rc;
}

/*
 * sip_alg_translate_via_addr - Translate a Via header address and/or port
 */
static int sip_alg_translate_via_addr(osip_via_t *v, const char *oaddr,
				      const char *taddr, const char *tport)
{
	char *p;

	p = osip_via_get_host(v);
	if (!sip_translate_addr_reqd(p, oaddr))
		return 0;

	osip_free(p);
	osip_via_set_host(v, osip_strdup(taddr));

	p = osip_via_get_port(v);
	if (sip_translate_port_reqd(p, tport)) {
		osip_free(p);
		osip_via_set_port(v, osip_strdup(tport));
	}
	return 0;
}

/*
 * sip_alg_translate_via - Translate Via header(s)
 */
static int sip_alg_translate_via(struct sip_alg_request *tsr,
				 const char *taddr, const char *tport)
{
	osip_via_t *v = NULL;
	int i = 0;
	int rc = 0;

	while (osip_message_get_via(tsr->sr_sip, i, &v) >= 0) {
		rc = sip_alg_translate_via_addr(v, sip_oaddr(tsr),
						taddr, tport);
		if (rc)
			return rc;
		i++;
	}
	return rc;
}

/*
 * sip_alg_translate_contact - Translate a Contact header
 */
static int sip_alg_translate_contact(struct sip_alg_request *tsr,
				     const char *taddr, const char *tport)
{
	osip_contact_t *c = NULL;
	int i = 0;
	int rc = 0;

	while (osip_message_get_contact(tsr->sr_sip, i, &c) >= 0) {
		rc = sip_alg_translate_url(osip_contact_get_url(c),
					   sip_oaddr(tsr), taddr, tport);
		if (rc)
			return rc;
		i++;
	}
	return rc;
}

/*
 * sip_alg_translate_record_route - Translate Record-Route header(s)
 */
static int sip_alg_translate_record_route(struct sip_alg_request *tsr,
					  const char *taddr, const char *tport)
{
	osip_record_route_t *rr;
	int i = 0;
	int rc = 0;

	while (osip_message_get_record_route(tsr->sr_sip, i, &rr) >= 0) {
		rc = sip_alg_translate_url(osip_record_route_get_url(rr),
					   sip_oaddr(tsr), taddr, tport);
		if (rc)
			return rc;
		i++;
	}
	return rc;
}

/*
 * sip_alg_translate_route - Translate a Route header
 *
 * The osip library parses either of the following two forms:
 *
 *   "Route: <sip:192.168.43.21;lr>,<sip:192.168.43.23;lr>\r\n"
 *
 * or
 *
 *   "Route: <sip:192.168.43.21;lr>\r\n"
 *   "Route: <sip:192.168.43.23;lr>\r\n"
 *
 * It always generates the second form on output (translating the url as where
 * relevant).
 */
static int sip_alg_translate_route(struct sip_alg_request *tsr,
				   const char *taddr, const char *tport)
{
	osip_route_t *r = NULL;
	int i = 0;
	int rc = 0;

	while (osip_message_get_route(tsr->sr_sip, i, &r) >= 0) {
		rc = sip_alg_translate_url(osip_route_get_url(r),
					   sip_oaddr(tsr), taddr, tport);
		if (rc)
			return rc;
		i++;
	}
	return rc;
}

/*
 * sip_alg_translate_request_uri - Translate a Request-Uri header
 */
static int sip_alg_translate_request_uri(struct sip_alg_request *tsr,
					 const char *taddr, const char *tport)
{
	osip_uri_t *r = tsr->sr_sip->req_uri;

	return sip_alg_translate_url(r, sip_oaddr(tsr), taddr, tport);
}

/*
 * Translate a generic SIP header that has not been parsed by the osip
 * library.
 *
 * Replace NAT target address with the translation address.  Also replaces the
 * port if 1. a port is present in the url, and 2. the header address matched
 * the target address.
 */
static int sip_alg_translate_header(osip_header_t *h, const char *oaddr,
				    const char *taddr, const char *tport)
{
	const char *p;

	if (!h)
		return 0;

	/*
	 * If the header does not contain NAT target address then there is
	 * nothing to be done
	 */
	p = strstr(h->hvalue, oaddr);
	if (!p)
		return 0;

	size_t oaddr_len = strlen(oaddr);
	size_t taddr_len = strlen(taddr);
	size_t tport_len = tport ? strlen(tport) : 0;
	size_t hval_len = strlen(h->hvalue);

	/* Ensure more than enough space */
	char buf[hval_len + taddr_len + tport_len + 1];
	char *insert_point = buf;

	/* copy part before oaddr */
	memcpy(insert_point, h->hvalue, p - h->hvalue);
	insert_point += p - h->hvalue;
	*insert_point = '\0';

	/* insert taddr */
	strncat(insert_point, taddr, taddr_len);
	insert_point += taddr_len;

	/* set p to point to just after oaddr */
	p += oaddr_len;

	/*
	 * replace port if tport specified by the caller and if a port is
	 * present in the header
	 */
	if (tport && *p == ':') {
		uint hport;
		const char *pp = p + 1;

		/* Look for a number at a point after the colon */
		if (sscanf(pp, "%5u", &hport) > 0 && hport <= 65535) {
			char hport_str[6];
			char *hportp;

			/*
			 * convert number to string, and locate in the
			 * original header string
			 */
			snprintf(hport_str, sizeof(hport_str), "%u", hport);
			hportp = strstr(pp, hport_str);

			/*
			 * Check that port string is immediately after the
			 * colon.  Only replace if header port is different
			 * than tport.
			 */
			if (hportp == pp && (strcmp(tport, hport_str) != 0)) {
				/* insert colon and tport */
				strcat(insert_point, ":");
				insert_point += 1;

				strncat(insert_point, tport, tport_len);
				insert_point += tport_len;

				/*
				 * set p to point just after the port in the
				 * original header string
				 */
				p = hportp + strlen(hport_str);
			}
		}
	}

	/*
	 * copy part after oaddr (or after port, if present), and NULL
	 * terminate
	 */
	strcat(insert_point, p);

	/* replace hvalue */
	char *new = osip_strdup(buf);
	if (!new)
		return -ENOMEM;

	osip_free(h->hvalue);
	h->hvalue = new;

	return 0;
}

/*
 * Translate all headers of the given name *if* the url contains oaddr.
 */
static int sip_alg_translate_header_byname(struct sip_alg_request *tsr,
					   const char *name,
					   const char *taddr,
					   const char *tport)
{
	osip_header_t *h;
	const char *oaddr = sip_oaddr(tsr);
	int i = 0;
	int rc;

	while ((i = osip_message_header_get_byname(tsr->sr_sip,
						   name,
						   i, &h)) >= 0) {
		rc = sip_alg_translate_header(h, oaddr, taddr, tport);

		if (rc < 0)
			return rc;
		i++;
	}
	return 0;
}

/*
 * Translate all P-asserted-identity headers
 */
static int sip_alg_translate_p_asserted_id(struct sip_alg_request *tsr,
					   const char *taddr,
					   const char *tport)
{
	return sip_alg_translate_header_byname(tsr,
					       "P-asserted-identity",
					       taddr, tport);
}

/*
 * Translate all P-preferred-identity headers
 */
static int sip_alg_translate_p_preferred_id(struct sip_alg_request *tsr,
					    const char *taddr,
					    const char *tport)
{
	return sip_alg_translate_header_byname(tsr,
					       "P-preferred-identity",
					       taddr, tport);
}

/*
 * sip_alg_translate_snat() - Translate for SNAT.
 */
static int sip_alg_translate_snat(struct sip_alg_request *tsr, bool forw,
				  const char *taddr, const char *tport)
{
	/*
	 * Translation fields depend upon both stream
	 * direction and msg type.
	 */
	if (MSG_IS_REQUEST(tsr->sr_sip) && forw) {
		if (sip_alg_translate_from(tsr, taddr, tport))
			return -1;
		if (sip_alg_translate_user_agent(tsr, taddr))
			return -1;
		if (sip_alg_translate_call_id(tsr, taddr))
			return -1;
		if (sip_alg_translate_via(tsr, taddr, tport))
			return -1;
		if (sip_alg_translate_contact(tsr, taddr, tport))
			return -1;
		if (sip_alg_translate_record_route(tsr, taddr, tport))
			return -1;
		if (sip_alg_translate_route(tsr, taddr, tport))
			return -1;
		if (sip_alg_translate_p_asserted_id(tsr, taddr, tport))
			return -1;
		if (sip_alg_translate_p_preferred_id(tsr, taddr, tport))
			return -1;
	} else if (MSG_IS_REQUEST(tsr->sr_sip) && !forw) {
		if (sip_alg_translate_request_uri(tsr, taddr, tport))
			return -1;
		if (sip_alg_translate_to(tsr, taddr, tport))
			return -1;
		if (sip_alg_translate_call_id(tsr, taddr))
			return -1;
	} else if (MSG_IS_RESPONSE(tsr->sr_sip) && forw) {
		if (sip_alg_translate_to(tsr, taddr, tport))
			return -1;
		if (sip_alg_translate_contact(tsr, taddr, tport))
			return -1;
		if (sip_alg_translate_record_route(tsr, taddr, tport))
			return -1;
		if (sip_alg_translate_from(tsr, taddr, tport))
			return -1;
		if (sip_alg_translate_call_id(tsr, taddr))
			return -1;
		if (sip_alg_translate_via(tsr, taddr, tport))
			return -1;
	} else if (MSG_IS_RESPONSE(tsr->sr_sip) && !forw) {
		if (sip_alg_translate_from(tsr, taddr, tport))
			return -1;
		if (sip_alg_translate_call_id(tsr, taddr))
			return -1;
		if (sip_alg_translate_via(tsr, taddr, tport))
			return -1;
		if (sip_alg_translate_record_route(tsr, taddr, tport))
			return -1;
		if (sip_alg_translate_route(tsr, taddr, tport))
			return -1;
	}
	return 0;
}

/*
 * sip_alg_translate_dnat() - Translate for DNAT.
 */
static int sip_alg_translate_dnat(struct sip_alg_request *tsr, bool forw,
				  const char *taddr, const char *tport)
{
	/*
	 * Translation fields depend upon both stream
	 * direction and msg type.
	 */
	if (MSG_IS_REQUEST(tsr->sr_sip) && forw) {
		if (sip_alg_translate_request_uri(tsr, taddr, tport))
			return -1;
		if (sip_alg_translate_to(tsr, taddr, tport))
			return -1;
	} else if (MSG_IS_REQUEST(tsr->sr_sip) && !forw) {
		if (sip_alg_translate_request_uri(tsr, taddr, tport))
			return -1;
		if (sip_alg_translate_contact(tsr, taddr, tport))
			return -1;
		if (sip_alg_translate_to(tsr, taddr, tport))
			return -1;
		if (sip_alg_translate_p_asserted_id(tsr, taddr, tport))
			return -1;
		if (sip_alg_translate_p_preferred_id(tsr, taddr, tport))
			return -1;
	} else if (MSG_IS_RESPONSE(tsr->sr_sip) && forw) {
		if (sip_alg_translate_to(tsr, taddr, tport))
			return -1;
		if (sip_alg_translate_record_route(tsr, taddr, tport))
			return -1;
		if (sip_alg_translate_route(tsr, taddr, tport))
			return -1;
	} else if (MSG_IS_RESPONSE(tsr->sr_sip) && !forw) {
		if (sip_alg_translate_request_uri(tsr, taddr, tport))
			return -1;
		if (sip_alg_translate_to(tsr, taddr, tport))
			return -1;
		if (sip_alg_translate_contact(tsr, taddr, tport))
			return -1;
		if (sip_alg_translate_record_route(tsr, taddr, tport))
			return -1;
		if (sip_alg_translate_route(tsr, taddr, tport))
			return -1;
	}
	return 0;
}

/*
 * sip_alg_translate_message() - Translate a sip msg.
 */
static int sip_alg_translate_message(const struct npf_alg *sip,
		struct sip_alg_request *sr, struct sip_alg_request **_tsr)
{
	int rc;
	struct sip_alg_request *tsr;

	*_tsr = NULL;

	tsr = sip_alg_request_alloc(false, sr->sr_if_idx);
	if (!tsr)
		return -ENOMEM;

	/* Store handle so we can ID requests from this session */
	tsr->sr_session = sr->sr_session;

	/*
	 * Clone the SIP and SDP messages.
	 */
	rc = osip_message_clone(sr->sr_sip, &tsr->sr_sip);
	if (rc)
		goto bad;

	memcpy(&tsr->sr_nat, &sr->sr_nat, sizeof(struct sip_nat));

	if (sr->sr_sdp) {
		rc = sdp_message_clone(sr->sr_sdp, &tsr->sr_sdp);
		if (rc)
			goto bad;
	}

	if (sip_is_snat(tsr)) {
		rc = sip_alg_translate_snat(tsr, sip_forw(tsr),
					    sip_taddr(tsr), sip_tport(tsr));
	} else  if (sip_is_dnat(tsr)) {
		rc = sip_alg_translate_dnat(tsr, sip_forw(tsr),
					    sip_taddr(tsr), sip_tport(tsr));
	}
	if (rc)
		goto bad;

	*_tsr = tsr;

	return 0;
bad:
	sip_alg_request_free(sip, tsr);
	return rc;
}

/*
 * sip_alg_update_payload() - Update a packet payload
 */
static int sip_alg_update_payload(npf_session_t *se, npf_cache_t *npc,
		const int di, struct rte_mbuf *nbuf,
		struct sip_alg_request *tsr)
{
	char *payload;
	char *sdp;
	osip_body_t *body;
	uint16_t new_plen;
	char ebuf[64];
	size_t sz;
	int rc;

	/*
	 * If we have an SDP, get the string and replace the body in
	 * the SIP.
	 */
	if (tsr->sr_sdp) {
		rc = sdp_message_to_str(tsr->sr_sdp, &sdp);
		if (rc) {
			rc = -ENOMEM;
			goto done;
		}

		/* Replace this body at pos = 0 */
		rc = osip_message_get_body(tsr->sr_sip, 0, &body);
		if (rc < 0) {
			rc = -ENOENT;
			osip_free(sdp);
			goto done;
		}
		osip_free(body->body);
		body->body = sdp;
		body->length = strlen(sdp);
	}

	osip_message_force_update(tsr->sr_sip);
	rc = osip_message_to_str(tsr->sr_sip, &payload, &sz);
	if (rc) {
		rc = -ENOMEM;
		goto done;
	}

	new_plen = (uint16_t) sz;

	rc = npf_payload_update(se, npc, nbuf, payload, di, new_plen);
	osip_free(payload);

done:
	if (rc) {
		if (net_ratelimit())
			RTE_LOG(ERR, FIREWALL,
				"NPF ALG: SIP payload update: %s\n",
				strerror_r(-rc, ebuf, sizeof(ebuf)));
	}

	return rc;
}

/*
 * sip_init_nat() - Init the 'nat' params for this request
 */
void sip_init_nat(struct sip_alg_request *sr, bool forw,
		  const npf_addr_t *taddr, const npf_addr_t *oaddr,
		  uint8_t alen, in_port_t tport, const int di)
{
	struct sip_nat *sn = &sr->sr_nat;
	int rc;

	/* Port and addr from nat struct for CNTL session */
	rc = snprintf(sn->sn_tport, 8, "%hu", ntohs(tport));
	if (rc < 0 || rc >= 8)
		return;

	if (taddr) {
		inet_ntop(AF_INET, taddr, sn->sn_taddr, sizeof(sn->sn_taddr));
		sn->sn_alen = alen;
	}
	if (oaddr)
		inet_ntop(AF_INET, oaddr, sn->sn_oaddr, sizeof(sn->sn_oaddr));
	sn->sn_di = di;
	sn->sn_forw = forw;

	if (taddr) {
		if (di == PFIL_IN && forw)
			sn->sn_type = sip_nat_dnat;
		else if (di == PFIL_OUT && forw)
			sn->sn_type = sip_nat_snat;
		else if (di == PFIL_IN && !forw)
			sn->sn_type = sip_nat_snat;
		else if (di == PFIL_OUT && !forw)
			sn->sn_type = sip_nat_dnat;
	} else {
		sn->sn_type = sip_nat_inspect;
	}
}

/*
 * sip_alg_manage_packet() - manage and translate SIP packets
 */
static int sip_alg_manage_packet(npf_session_t *se, struct sip_alg_request *sr,
			npf_cache_t *npc, struct rte_mbuf *nbuf, npf_nat_t *nat)
{
	struct sip_alg_request *tsr = NULL;
	struct npf_alg *sip = npf_alg_session_get_alg(se);
	int rc;
	bool consumed = false;

	rc = sip_alg_translate_message(sip, sr, &tsr);
	if (rc)
		goto done;

	rc = sip_alg_manage_sip(se, npc, sr, tsr, nat, &consumed);
	if (rc)
		goto done;

	rc = sip_alg_update_payload(se, npc, sip_di(tsr), nbuf, tsr);
	if (rc) {
		if (consumed) {
			sip_request_lookup_and_expire(sip, tsr);
			consumed = false;
		}
	}

done:
	if (!consumed)
		sip_alg_request_free(sip, tsr);

	sip_alg_request_free(sip, sr);

	return rc;
}

/*
 * sip_alg_translate_packet()
 */
int sip_alg_translate_packet(npf_session_t *se, npf_cache_t *npc,
			     npf_nat_t *ns, struct rte_mbuf *nbuf,
			     struct npf_alg *sip, const int di)
{
	npf_addr_t taddr;
	in_port_t tport;
	npf_addr_t oaddr;
	in_port_t oport;
	bool forw;
	struct sip_alg_request *sr;

	/* Don't manipulate (TCP) packets w/o data */
	if (!npf_payload_len(npc))
		return 0;

	/*
	 * Parsed msg may have been placed into session private data by tuple
	 * inspect
	 */
	sr = sip_alg_parse(se, npc, nbuf);
	if (!sr)
		return -EINVAL;

	if (sip_alg_verify(sr)) {
		sip_alg_request_free(sip, sr);
		return -EINVAL;
	}

	(void) npf_session_retnat(se, di, &forw);

	/*
	 * We need both sets of addrs, in opposite order
	 */
	if (forw) {
		npf_nat_get_trans(ns, &taddr, &tport);
		npf_nat_get_orig(ns, &oaddr, &oport);
	} else {
		npf_nat_get_orig(ns, &taddr, &tport);
		npf_nat_get_trans(ns, &oaddr, &oport);
	}

	/*
	 * For the SIP alt cntl session, 'forw' is true since the session was
	 * created in this direction.  However from the SIP translation POV,
	 * we want to use the parent session to get the 'forw' setting, since
	 * the SIP packet flow is relative to it.  This is used to set sn_forw
	 * and sn_type in the sip_nat struct that hangs of the SIP request
	 * struct.
	 */
	if (npf_session_get_parent(se) &&
	    npf_alg_session_test_flag(se, SIP_ALG_REVERSE))
		forw = !forw;

	sip_init_nat(sr, forw, &taddr, &oaddr, npc->npc_alen, tport, di);

	return sip_alg_manage_packet(se, sr, npc, nbuf, ns);
}
