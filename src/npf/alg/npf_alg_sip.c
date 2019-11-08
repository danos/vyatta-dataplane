/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
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
#include <osip2/osip.h>
#include <osipparser2/headers/osip_call_id.h>
#include <osipparser2/headers/osip_contact.h>
#include <osipparser2/headers/osip_content_type.h>
#include <osipparser2/headers/osip_cseq.h>
#include <osipparser2/headers/osip_from.h>
#include <osipparser2/headers/osip_header.h>
#include <osipparser2/headers/osip_record_route.h>
#include <osipparser2/headers/osip_route.h>
#include <osipparser2/headers/osip_via.h>
#include <osipparser2/osip_body.h>
#include <osipparser2/osip_list.h>
#include <osipparser2/osip_message.h>
#include <osipparser2/osip_parser.h>
#include <osipparser2/osip_port.h>
#include <osipparser2/osip_uri.h>
#include <osipparser2/sdp_message.h>
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
#include "npf/alg/npf_alg_private.h"
#include "npf/npf_cache.h"
#include "npf/npf_nat.h"
#include "npf/npf_session.h"
#include "urcu.h"
#include "util.h"
#include "vplane_log.h"

struct ifnet;
struct rte_mbuf;
struct sip_alg_request;

/* default port */
#define SIP_DEFAULT_PORT	5060

/*
 * Minimum msg size.
 *
 * While the protocol does not define a minimum size directly, the Osip
 * parser assumes minimum of 4 bytes during parsing.
 *
 * A 'real' SIP message must have multiple header fields to be valid and
 * a minimum ACK msg with options stripped out will be > 200 bytes,
 * so let's use that as our min msg size.
 */
#define SIP_MSG_MIN_LENGTH	200

/*
 * Default lifetime for a request in the hash table.
 */
#define SIP_DEFAULT_REQUEST_TIMEOUT 32

/*
 * Flags defining the types of SIP/media
 * flows.  Note that a SIP media UDP flow
 * is handled as a RTP flow.
 */
#define SIP_ALG_CNTL_FLOW	0x01
#define SIP_ALG_ALT_CNTL_FLOW	0x02
#define SIP_ALG_RTP_FLOW	0x04
#define SIP_ALG_RTCP_FLOW	0x08
#define SIP_ALG_REVERSE		0x10
#define SIP_ALG_NAT		0x20
#define SIP_ALG_ALT_TUPLE_SET	0x40
#define SIP_ALG_MASK		(SIP_ALG_CNTL_FLOW | SIP_ALG_ALT_CNTL_FLOW | \
				 SIP_ALG_RTP_FLOW | SIP_ALG_RTCP_FLOW)

/* Hash table config */
#define SIP_HT_INIT	32
#define SIP_HT_MIN	32
#define SIP_HT_MAX	1024

/* SIP per-packet flags. */
#define SIP_NPC_REQUEST		0x01
#define SIP_NPC_RESPONSE	0x02

/* For one-time initialization of libosip. */
static osip_t		*sip_osip;

/*
 * We manage Invites and responses by using a hash table.
 * New invites are added to the table, and corresponding responses
 * pull them from the hash table.
 */
struct sip_private {
	struct cds_lfht		*sp_ht;
	rte_spinlock_t		sp_media_lock; /* For media */
	struct cds_list_head	sp_dead_media; /* for freeing media */
};

/*
 *  Max media connections per INVITE.
 */
#define SDP_MAX_MEDIA 8

/*
 * There are two types of media that we are interested in: UDP and RTP.
 * (RTP includes secure RTP)
 */
enum sdp_proto {
	sdp_proto_udp = 1,
	sdp_proto_rtp,
	sdp_proto_unknown
};

/*
 * Type of nat being performed.
 */
enum sip_nat_type {
	sip_nat_snat = 1,
	sip_nat_dnat,
	sip_nat_inspect
};

/*
 * Struct for holding nat info.
 */
struct sip_nat {
	char			sn_taddr[INET6_ADDRSTRLEN];/* trans addr */
	char			sn_oaddr[INET6_ADDRSTRLEN];/* orig addr */
	char			sn_tport[8];	/* trans port */
	enum sip_nat_type	sn_type;	/* type of nat */
	bool			sn_forw;	/* forward? */
	int			sn_di;		/* direction */
	uint8_t			sn_alen;	/* addr len */
};

#define sip_nat_type(sr)	((sr)->sr_nat.sn_type)
#define sip_is_snat(sr)		(sip_nat_type(sr) == sip_nat_snat)
#define sip_is_dnat(sr)		(sip_nat_type(sr) == sip_nat_dnat)
#define sip_is_inspect(sr)	(sip_nat_type(sr) == sip_nat_inspect)
#define sip_forw(sr)		((sr)->sr_nat.sn_forw)
#define sip_taddr(sr)		((sr)->sr_nat.sn_taddr)
#define sip_oaddr(sr)		((sr)->sr_nat.sn_oaddr)
#define sip_tport(sr)		((sr)->sr_nat.sn_tport)
#define sip_di(sr)		((sr)->sr_nat.sn_di)

/* Macros for accessing SIP instance datum */
#define sip_alg_instance(sip)  ((sip)->na_ai)

#define SIP_REQUEST_EXPIRED	0x1
#define SIP_REQUEST_REMOVING	0x2

/*
 * SIP request struct
 */
struct sip_alg_request {
	struct cds_lfht_node	sr_node;
	uint64_t		sr_timeout;
	osip_message_t		*sr_sip;
	sdp_message_t		*sr_sdp;
	struct sip_nat		sr_nat;
	uint32_t		sr_if_idx;
	struct cds_list_head	sr_media;
	uint8_t			sr_flags;
	const struct npf_alg	*sr_sip_alg;
	struct rcu_head		sr_rcu_head;
};

/*
 * Struct for matching hash table requests
 */
struct sip_request_match {
	osip_call_id_t *sm_call_id;
	uint32_t	sm_if_idx;
};


/*
 * Struct for managing rtp translation data. Note
 * these ports are maintained in host order.
 *
 * We have to save both the original and translation
 * ports and addresses until we create the tuples.
 */
struct sip_alg_media {
	struct cds_list_head	m_list;		/* list head */

	enum sdp_proto		m_proto;
	enum sip_nat_type	m_type;

	/* Original */
	in_port_t		m_rtp_port;
	npf_addr_t		m_rtp_addr;
	uint8_t			m_rtp_alen;
	in_port_t		m_rtcp_port;
	npf_addr_t		m_rtcp_addr;
	uint8_t			m_rtcp_alen;

	/* Translated */
	in_port_t		m_trtp_port;
	npf_addr_t		m_trtp_addr;
	uint8_t			m_trtp_alen;
	in_port_t		m_trtcp_port;
	npf_addr_t		m_trtcp_addr;
	uint8_t			m_trtcp_alen;

	npf_natpolicy_t		*m_np;
	npf_rule_t		*m_rl;
	uint32_t		m_nat_flags;
	vrfid_t			m_vrfid;
	bool			m_rtp_reserved;	/* ports from pool? */
	bool			m_rtcp_reserved;
};

/*
 * struct for parsing the rtcp attribute (RFC3605)
 */
struct sip_rtcp {
	char *rtcp_port;
	char *rtcp_nettype;
	char *rtcp_addrtype;
	char *rtcp_addr;
};

/*
 * Struct for managing tuple data.  These are added to media (RTP and RTCP)
 * tuples.
 *
 * Note ports are in host format.
 */
struct sip_tuple_data {
	const struct npf_alg	*td_sip;
	struct sip_nat		td_nat;
	struct sip_alg_media	*td_mi;
	struct sip_alg_media	*td_mr;
	struct npf_alg_tuple	*td_nt1; /* For the tuples */
	struct npf_alg_tuple	*td_nt2;
	rte_atomic32_t		td_refcnt;
	bool			td_is_reverse; /* Reverse flow? */
};
#define td_nat_type(sr)		((td)->td_nat.sn_type)
#define td_is_snat(td)		((td)->td_nat.sn_type == sip_nat_snat)
#define td_is_dnat(td)		((td)->td_nat.sn_type == sip_nat_dnat)
#define td_is_inspect(td)	((td)->td_nat.sn_type == sip_nat_inspect)
#define td_is_reverse(td)	((td)->td_is_reverse)
#define td_forw(td)		((td)->td_nat.sn_forw)

/*
 * SIP ALG session.
 */
struct sip_alg_session {
	in_port_t		ss_via_port;
	uint8_t			ss_via_alen;
	uint32_t		ss_ifx;
	npf_addr_t		ss_via_addr;
	int			ss_call_id_count;
	osip_call_id_t		**ss_call_ids;
};

/*
 * sip_alg_release_translation() - Release preallocated translation data.
 */
static void sip_alg_release_translation(struct sip_alg_media *m,
		npf_addr_t taddr, in_port_t port)
{

	if (m->m_np)
		npf_nat_free_map(m->m_np, m->m_rl,
				m->m_nat_flags, m->m_vrfid, taddr, htons(port));
}

/*
 * Free a ports struct, if the ports were
 * allocated from a nat pool, return them.
 */
static void sip_media_free(void *_m)
{
	struct sip_alg_media *m = _m;

	if (!m)
		return;
	if (m->m_type != sip_nat_inspect) {
		if (m->m_rtp_reserved)
			sip_alg_release_translation(m,
					m->m_trtp_addr, m->m_trtp_port);
		if (m->m_rtcp_reserved)
			sip_alg_release_translation(m,
					m->m_trtcp_addr, m->m_trtcp_port);
	}
	free(m);
}

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
		rte_atomic32_set(&td->td_refcnt, 1);
		td->td_is_reverse = false;
	}
	return td;
}

/*
 * sip_tuple_data_get()
 */
static inline void sip_tuple_data_get(struct sip_tuple_data *td)
{
	rte_atomic32_inc(&td->td_refcnt);
}

/*
 * stip_tuple_data_put()
 */
static void sip_tuple_data_put(struct sip_tuple_data *td)
{
	if (rte_atomic32_dec_and_test(&td->td_refcnt)) {
		sip_media_free(td->td_mi);
		sip_media_free(td->td_mr);
		free(td);
	}
}

/*
 * sip_media_count()
 */
static int sip_media_count(struct cds_list_head *h)
{
	struct cds_list_head *p;
	int i = 0;

	cds_list_for_each(p, h)
		i++;

	return i;
}

/*
 * sip_addr_from_str() - Convert a string addr into an Ipv4 or IPv6 addr
 */
static void sip_addr_from_str(const char *saddr, npf_addr_t *addr,
				uint8_t *alen)
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
 * sip_addr_to_str() Convert npf addr to a string
 */
static char *sip_addr_to_str(npf_addr_t *a, uint8_t alen)
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
static char *port_to_str(in_port_t n)
{
	char buf[8];
	int rc;

	rc = snprintf(buf, 8, "%hu", n);
	if (rc < 0 || rc > 6)
		return NULL;
	return osip_strdup(buf);
}

/* Free dead media structs from the instance */
static void sip_free_dead_media(struct sip_private *sp)
{
	struct sip_alg_media *m;
	struct sip_alg_media *tmp;

	if (!sp)
		return;

	rte_spinlock_lock(&sp->sp_media_lock);
	cds_list_for_each_entry_safe(m, tmp, &sp->sp_dead_media, m_list) {
		cds_list_del(&m->m_list);
		sip_media_free(m);
	}
	rte_spinlock_unlock(&sp->sp_media_lock);
}

static void sip_request_free_rcu(struct rcu_head *head)
{
	struct sip_alg_request *sr = caa_container_of(head,
				struct sip_alg_request, sr_rcu_head);
	struct sip_private *sp = sr->sr_sip_alg->na_private;

	/*
	 * Move medias to the instance for deletion
	 * via the sip GC
	 */
	if (sp) {
		rte_spinlock_lock(&sp->sp_media_lock);
		cds_list_splice(&sr->sr_media, &sp->sp_dead_media);
		rte_spinlock_unlock(&sp->sp_media_lock);
	}

	if (sr->sr_sip)
		osip_message_free(sr->sr_sip);
	if (sr->sr_sdp)
		sdp_message_free(sr->sr_sdp);
	free(sr);
}

/*
 * Free a sip msg, always via RCU.
 */
static void sip_alg_request_free(const struct npf_alg *sip,
		struct sip_alg_request *sr)
{
	if (sr) {
		sr->sr_sip_alg = sip;
		call_rcu(&sr->sr_rcu_head, sip_request_free_rcu);
	}
}

/*
 * Synchronously free a sip msg.
 * Used when destroying the sip instance.
 */
static void sip_alg_request_free_sync(const struct npf_alg *sip,
		struct sip_alg_request *sr)
{
	if (sr) {
		sr->sr_sip_alg = sip;
		/* Call the rcu free variant synchronously */
		sip_request_free_rcu(&sr->sr_rcu_head);
	}
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
 * sip_alg_request_alloc()
 */
static struct sip_alg_request *sip_alg_request_alloc(bool init_sip,
		uint32_t if_idx)
{
	struct sip_alg_request *sr;

	sr = calloc(1, sizeof(struct sip_alg_request));
	if (!sr)
		return NULL;

	CDS_INIT_LIST_HEAD(&sr->sr_media);
	sr->sr_if_idx = if_idx;

	if (init_sip && osip_message_init(&sr->sr_sip)) {
		free(sr);
		sr = NULL;
	}

	return sr;
}

/*
 * Parse a sip packet
 */
static struct sip_alg_request *sip_alg_parse(const struct npf_alg *sip,
		npf_cache_t *npc, uint32_t if_idx, struct rte_mbuf *nbuf)
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

/*
 * sip_ht_match() - Match function for hash table
 */
static int sip_ht_match(struct cds_lfht_node *node, const void *key)
{
	const struct sip_alg_request *sr = caa_container_of(node,
			struct sip_alg_request, sr_node);
	const struct sip_request_match *sm = key;

	if (sr->sr_flags & SIP_REQUEST_EXPIRED)
		return 0;

	if (sm->sm_if_idx != sr->sr_if_idx)
		return 0;

	return !osip_call_id_match(osip_message_get_call_id(sr->sr_sip),
			sm->sm_call_id);
}

/*
 * sip_request_expire() - Expire an invite from the hash table.
 */
static void sip_request_expire(struct sip_alg_request *sr)
{
	if (!(sr->sr_flags & SIP_REQUEST_EXPIRED))
		sr->sr_flags |= SIP_REQUEST_EXPIRED;
}

/*
 * sip_delete_request() - Delete an invite from the hash table.
 */
static void sip_delete_request(struct npf_alg *sip,
		struct sip_alg_request *sr)
{
	struct sip_private *sp = sip->na_private;

	if (sr && sp && !cds_lfht_del(sp->sp_ht, &sr->sr_node))
		sip_alg_request_free(sip, sr);
}

static bool sip_ht_expired(uint64_t curr, struct sip_alg_request *sr)
{
	if (sr->sr_flags & SIP_REQUEST_EXPIRED)
		return true;
	if (sr->sr_timeout < curr) {
		sip_request_expire(sr);
		return true;
	}
	return false;
}

/*
 * sip_ht_gc()  - Clean stale entries from the hash table.
 */
static void sip_ht_gc(struct npf_alg *sip)
{
	struct cds_lfht_iter iter;
	struct sip_alg_request *sr;
	uint64_t current = rte_get_timer_cycles();
	struct sip_private *sp = sip->na_private;

	if (!sp)
		return;

	/* Always free any medias first */
	sip_free_dead_media(sp);

	cds_lfht_for_each_entry(sp->sp_ht, &iter, sr, sr_node) {
		if (!sip_ht_expired(current, sr))
			continue;

		if (sr->sr_flags & SIP_REQUEST_REMOVING)
			sip_delete_request(sip, sr);
		else
			sr->sr_flags |= SIP_REQUEST_REMOVING;
	}
}

/*
 * sip_alg_hash() -  Create a hash out of the Call-ID number. This is unique.
 */
static unsigned long sip_alg_hash(struct sip_request_match *sm)
{
	char *tmp;
	unsigned long hash = 0;

	if (!sm->sm_call_id)
		return hash;

	tmp = osip_call_id_get_number(sm->sm_call_id);
	if (tmp)
		hash = rte_jhash(tmp, strlen(tmp), hash);

	tmp = osip_call_id_get_host(sm->sm_call_id);
	if (tmp)
		hash = rte_jhash(tmp, strlen(tmp), hash);

	return hash ? rte_jhash_1word(sm->sm_if_idx, hash) : 0;
}

/*
 * sip_request_lookup_by_call_id() - Lookup by call id.
 */
static struct sip_alg_request *sip_request_lookup_by_call_id(
		const struct npf_alg *sip, uint32_t if_idx,
		osip_call_id_t *call_id)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	unsigned long hash;
	struct sip_alg_request *sr;
	struct sip_private *sp;
	struct sip_request_match sm = {
		.sm_call_id = call_id,
		.sm_if_idx = if_idx
	};

	if (!sip)
		return NULL;

	sp = sip->na_private;
	if (!sp)
		return NULL;

	hash = sip_alg_hash(&sm);
	if (!hash)
		return NULL;

	cds_lfht_lookup(sp->sp_ht, hash, sip_ht_match, &sm, &iter);
	node = cds_lfht_iter_get_node(&iter);
	if (node)
		sr = caa_container_of(node, struct sip_alg_request, sr_node);
	else
		sr = NULL;

	return sr;
}

/*
 * sip_request_lookup() - Lookup a request
 */
static struct sip_alg_request *sip_request_lookup(const struct npf_alg *sip,
		struct sip_alg_request *incoming)
{
	osip_call_id_t *call_id;

	call_id = osip_message_get_call_id(incoming->sr_sip);
	return sip_request_lookup_by_call_id(sip, incoming->sr_if_idx, call_id);
}

/* Expire all SIP requests on this session handle */
static void sip_expire_session_request(npf_session_t *se)
{
	struct sip_alg_session *ss = npf_alg_session_get_private(se);
	const struct npf_alg *sip = npf_alg_session_get_alg(se);
	struct sip_alg_request *sr;
	uint32_t if_idx = npf_session_get_if_index(se);
	int i;

	if (!ss)
		return;

	for (i = 0 ; i < ss->ss_call_id_count; i++) {
		sr = sip_request_lookup_by_call_id(sip, if_idx,
				ss->ss_call_ids[i]);
		if (sr)
			sip_request_expire(sr);
		/* free this call id */
		osip_call_id_free(ss->ss_call_ids[i]);
	}

	/* reset so expire/destroy doesn't repeat */
	ss->ss_call_id_count = 0;
	free(ss->ss_call_ids);
	ss->ss_call_ids = NULL;
}

/*
 * sip_request_lookup_and_expire() - Expire an invite from the hash table.
 */
static void sip_request_lookup_and_expire(const struct npf_alg *sip,
		struct sip_alg_request *incoming)
{
	struct sip_alg_request *sr;

	if (incoming) {
		sr = sip_request_lookup(sip, incoming);
		if (sr)
			sip_request_expire(sr);
	}
}

/*
 * sip_alg_expires() - Get an expiration time for this request
 */
static uint64_t sip_alg_expires(struct sip_alg_request *sr)
{
	osip_header_t *expires;
	unsigned long timeout = 0;
	char *end;
	int rc;

	/* Does the request have an expires field? */
	rc = osip_message_get_expires(sr->sr_sip, 0, &expires);
	if (rc >= 0 && expires->hvalue) {
		timeout = strtoul(expires->hvalue, &end, 10);
		if (*end)
			timeout = 0;
	}

	/*
	 * If unset or bogus, or greater than 24h, set a default.
	 */
	if (!timeout || timeout > 84600)
		timeout = SIP_DEFAULT_REQUEST_TIMEOUT;

	return (uint64_t) timeout;
}

/*
 * sip_alg_add_invite() - Add an invite to the hash table.
 */
static int sip_alg_add_invite(const struct npf_alg *sip,
			      struct sip_alg_request *sr)
{
	unsigned long hash;
	struct cds_lfht_node *node;
	struct sip_request_match sm;
	struct sip_private *sp = sip->na_private;

	if (!MSG_IS_INVITE(sr->sr_sip))
		return -EINVAL;

	if (!sp)
		return -EINVAL;

	sm.sm_call_id = osip_message_get_call_id(sr->sr_sip);
	sm.sm_if_idx = sr->sr_if_idx;
	hash = sip_alg_hash(&sm);
	if (!hash)
		return -EINVAL;

	cds_lfht_node_init(&sr->sr_node);
	sr->sr_timeout = sip_alg_expires(sr);
	sr->sr_timeout *= rte_get_timer_hz(); /* to cycles */
	sr->sr_timeout += rte_get_timer_cycles(); /* add current time */

	node = cds_lfht_add_unique(sp->sp_ht, hash, sip_ht_match, &sm,
					&sr->sr_node);
	if (node != &sr->sr_node)
		return -EEXIST;

	return 0;
}

/*
 * Create and add a tuple from a session, but with a wildcard source port.
 * This tuple is subsequently expired when the SIP Request is expired.
 */
static int sip_alg_add_cntl_tuple(npf_session_t *se, npf_cache_t *npc)
{
	struct npf_alg_tuple *nt;
	const struct npf_alg *sip = npf_alg_session_get_alg(se);
	int rc;

	nt = npf_alg_tuple_alloc();
	if (!nt)
		return -ENOMEM;

	nt->nt_se = se;
	nt->nt_alg = sip;
	nt->nt_ifx = npf_session_get_if_index(se);
	nt->nt_flags = NPF_TUPLE_MATCH_ANY_SPORT | NPF_TUPLE_KEEP |
		NPF_TUPLE_MULTIMATCH;
	nt->nt_alg_flags = SIP_ALG_ALT_CNTL_FLOW;
	nt->nt_proto = IPPROTO_UDP;
	nt->nt_alen = 4;

	nt->nt_sport = 0;	/* Any source port */
	nt->nt_srcip = *npf_cache_dstip(npc);
	npf_nat_get_trans(npf_session_get_nat(se), &nt->nt_dstip,
			&nt->nt_dport);

	rc = npf_alg_tuple_insert(sip_alg_instance(sip), nt);
	if (rc)
		npf_alg_tuple_free(nt);
	else
		npf_alg_session_set_flag(se, SIP_ALG_ALT_TUPLE_SET);
	return rc;
}

/*
 * Add a control tuple if we are using SNAT.  Cisco SIP Gateways send SIP
 * response messages with a (per-call?) random source port.  This sets up a
 * tuple in the reverse direction (c/w with REQUEST) that matches on any
 * source port.
 */
static int sip_alg_manage_cntl(npf_session_t *se, npf_cache_t *npc,
		struct sip_alg_request *sr)
{
	struct sip_alg_session *ss;
	uint32_t flags = npf_alg_session_get_flags(se);

	/* Already added? */
	if (flags & SIP_ALG_ALT_TUPLE_SET)
		return 0;

	/* Only if this is a UDP connection. */
	if (npf_session_get_proto(se)  != IPPROTO_UDP)
		return 0;

	/* Only add from a CNTL session. */
	if (!(flags & SIP_ALG_CNTL_FLOW))
		return 0;

	ss = npf_alg_session_get_private(se);
	if (!ss)
		return 0;

	/* Only in forward direction */
	if (!sip_forw(sr))
		return 0;

	/* Currently only supports SNAT */
	if (!sip_is_snat(sr))
		return 0;

	return sip_alg_add_cntl_tuple(se, npc);
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

/*
 * sip_alg_verify() - Some cursory checks before dealing with this packet.
 */
static int sip_alg_verify(struct sip_alg_request *sr)
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
 * sip_translate_addr_reqd() - Do we want to translate this addr?
 */
static inline bool sip_translate_addr_reqd(const char *addr, const char *oaddr)
{
	if (!addr || !oaddr)
		return false;

	/* Only translate if the address matches the NAT target address */
	if (strcmp(addr, oaddr) != 0)
		return false;

	return true;
}

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
			if (hportp == pp && strcmp(tport, hport_str)) {
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
 * sip_alg_set_rtcp_attribute() - Update "rtcp" attribute if present
 */
static int sip_alg_sdp_set_rtcp_attribute(struct sip_alg_request *sr,
		int pos, npf_addr_t *taddr, uint8_t alen, in_port_t tport)
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
			rc = npf_nat_alloc_map(np, rl, nat_flags,
					vrfid, &m->m_trtcp_addr, &port, 1);
			if (rc)
				return rc;
			m->m_trtcp_port = ntohs(port);
			m->m_trtcp_alen = m->m_rtcp_alen;
			m->m_rtcp_reserved = true;
		} else{
			m->m_trtcp_addr = m->m_rtcp_addr;
			m->m_trtcp_port = m->m_rtcp_port;
			m->m_trtcp_alen = m->m_rtcp_alen;
		}
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

	if (strcmp(c->c_nettype, "IN"))
		return -EINVAL;

	if (!strcmp(c->c_addrtype, "IP6"))
		return 0;

	if (strcmp(c->c_addrtype, "IP4"))
		return -EINVAL;

	osip_free(c->c_addr);
	c->c_addr = addr;
	return 0;
}

static int sip_alg_translate_media_port(struct sip_alg_request *sr,
				int pos, in_port_t port)
{
	char *cport;

	cport = port_to_str(port);
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
 * Translate the SDP session (global) connection address
 */
static void
sip_alg_update_session_media(struct sip_alg_request *sr)
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
 * sip_alg_sdp_update_origin() - Update the "o=" field.
 */
static int sip_alg_sdp_update_origin(struct sip_alg_request *sr)
{
	char *nettype = sdp_message_o_nettype_get(sr->sr_sdp);
	char *addrtype = sdp_message_o_addrtype_get(sr->sr_sdp);

	if (!nettype || strcmp(nettype, "IN"))
		return -EINVAL;

	if (addrtype && !strcmp(addrtype, "IP6"))
		return 0;  /* Ignore IPv6 */

	if (!addrtype || strcmp(addrtype, "IP4"))
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

/*
 * sip_media_alloc() - Allocate a media struct
 */
static struct sip_alg_media *sip_media_alloc(npf_session_t *se,
					struct sip_alg_request *sr, int pos)
{
	struct sip_alg_media *m;
	npf_nat_t *nat = npf_session_get_nat(se);

	m = calloc(1, sizeof(struct sip_alg_media));
	if (!m)
		return NULL;

	CDS_INIT_LIST_HEAD(&m->m_list);
	m->m_np = npf_nat_get_policy(nat);
	if (m->m_np) {
		m->m_rl = npf_nat_get_rule(nat);
		m->m_nat_flags = npf_nat_get_map_flags(nat);
		m->m_vrfid = npf_session_get_vrfid(se);
	}

	m->m_proto = sip_alg_sdp_get_media_proto(sr, pos);
	m->m_type = sip_nat_type(sr);
	return m;
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

static int sip_alg_translate_media(struct sip_alg_request *sr,
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
 * sip_parse_reply_path() - Parse the first VIA for reply path parameters.
 */
static int sip_parse_reply_path(struct sip_alg_request *sr, npf_session_t *se)
{
	struct sip_alg_session *ss = npf_alg_session_get_private(se);
	int rc;

	/*
	 * The SIP RFC states that responses are always routed to the
	 * VIA path.  In the case of newer Cicso phones, a high number
	 * sport is used with replies expected on the SIP default port
	 * (5060).  See the inspect and nat routines for more details.
	 *
	 * This means we may need to translate all replies after
	 * receiving the first msg.  So grab the needed addr/port here and
	 * save it in the session handle.
	 */

	if (!ss)
		return -ENOENT;

	rc = 0;
	if (!ss->ss_via_port) {
		osip_via_t *v = NULL;

		ss->ss_ifx = npf_session_get_if_index(se);
		osip_message_get_via(sr->sr_sip, 0, &v);
		if (v) {
			ss->ss_via_port = htons(npf_port_from_str(
							osip_via_get_port(v)));
			if (!ss->ss_via_port)
				return -EINVAL;

			/*
			 * Note, this my fail if the VIA address is a FQDN, in
			 * which case ss_via_alen will be left at 0.
			 */
			ss->ss_via_alen = 0;
			sip_addr_from_str(osip_via_get_host(v),
					  &ss->ss_via_addr, &ss->ss_via_alen);
			rc = 0;

		} else
			rc = -EINVAL;
	}
	return rc;
}

/*
 * sip_alg_manage_media() - Parse a media line, reserve addr/port and
 */
static int sip_alg_manage_media(npf_session_t *se, npf_nat_t *nat,
				struct sip_alg_request *sr)
{
	int rc;
	int pos;
	struct sip_alg_media *m;

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

		rc = -ENOMEM;
		m = sip_media_alloc(se, sr, pos);
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

		cds_list_add_tail(&sr->sr_media, &m->m_list);
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
 * sip_tuple_data_free() - ALG tuple callback for tuple private data.
 */
static void sip_tuple_data_free(void *data)
{
	struct sip_tuple_data *td = data;

	if (td)
		sip_tuple_data_put(td);
}

static void sip_alg_tuple_init(struct npf_alg_tuple *nt, npf_session_t *se,
		void *data, uint8_t alen)
{
	const struct npf_alg *sip = npf_alg_session_get_alg(se);

	/* session ref count is incremented by apt_insert_tuple */
	nt->nt_se = se;
	nt->nt_alg = sip;
	nt->nt_ifx = npf_session_get_if_index(se);
	nt->nt_flags = NPF_TUPLE_MATCH_ALL;
	nt->nt_timeout = 10;
	nt->nt_proto = IPPROTO_UDP;
	nt->nt_alen = alen;

	if (data) {
		nt->nt_data = data;
		nt->nt_reap = sip_tuple_data_free;
	}
}

static int sip_alloc_tuple_pair(struct npf_alg_tuple **forward,
		struct npf_alg_tuple **reverse)
{
	*reverse = NULL;
	*forward = npf_alg_tuple_alloc();
	if (!*forward)
		goto bad;

	*reverse = npf_alg_tuple_alloc();
	if (!*reverse)
		goto bad;

	return 0;

bad:
	npf_alg_tuple_free(*forward);
	npf_alg_tuple_free(*reverse);
	*forward = NULL;
	*reverse = NULL;
	return -ENOMEM;
}

/*
 * sip_alg_create_rtcp_tuple()
 */
static void sip_alg_create_rtcp_tuples(npf_session_t *se, npf_cache_t *npc,
			struct sip_tuple_data *td)
{
	int rc;
	struct sip_alg_media *mi = td->td_mi;
	struct sip_alg_media *mr = td->td_mr;
	const struct npf_alg *sip = npf_alg_session_get_alg(se);
	struct npf_alg_tuple *forward;
	struct npf_alg_tuple *reverse;

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

	/* Allocate a pair of tuples */
	if (sip_alloc_tuple_pair(&forward, &reverse))
		return;

	/* Common init */
	sip_alg_tuple_init(forward, se, td, npc->npc_alen);
	sip_alg_tuple_init(reverse, se, td, npc->npc_alen);
	forward->nt_alg_flags = SIP_ALG_RTCP_FLOW;
	reverse->nt_alg_flags = SIP_ALG_RTCP_FLOW;

	/* Set ports/addrs/flags */
	switch (td_nat_type(td)) {
	case sip_nat_snat:
		forward->nt_alg_flags |= SIP_ALG_NAT;
		forward->nt_srcip = mi->m_rtcp_addr;
		forward->nt_sport = htons(mi->m_rtcp_port);
		forward->nt_dstip = mr->m_trtcp_addr;
		forward->nt_dport = htons(mr->m_trtcp_port);

		reverse->nt_alg_flags |= SIP_ALG_NAT;
		reverse->nt_srcip = mr->m_rtcp_addr;
		reverse->nt_sport = htons(mr->m_rtcp_port);
		reverse->nt_dstip = mi->m_trtcp_addr;
		reverse->nt_dport = htons(mi->m_trtcp_port);
		break;
	case sip_nat_dnat:
		forward->nt_alg_flags |= SIP_ALG_NAT;
		forward->nt_srcip = mi->m_rtcp_addr;
		forward->nt_sport = htons(mi->m_rtcp_port);
		forward->nt_dstip = mr->m_rtcp_addr;
		forward->nt_dport = htons(mr->m_rtcp_port);

		reverse->nt_alg_flags |= SIP_ALG_NAT;
		reverse->nt_srcip = mr->m_trtcp_addr;
		reverse->nt_sport = htons(mr->m_trtcp_port);
		reverse->nt_dstip = mi->m_rtcp_addr;
		reverse->nt_dport = htons(mi->m_rtcp_port);
		break;
	case sip_nat_inspect:
		forward->nt_srcip = mi->m_rtcp_addr;
		forward->nt_sport = htons(mi->m_rtcp_port);
		forward->nt_dstip = mr->m_rtcp_addr;
		forward->nt_dport = htons(mr->m_rtcp_port);

		reverse->nt_srcip = mr->m_rtcp_addr;
		reverse->nt_sport = htons(mr->m_rtcp_port);
		reverse->nt_dstip = mi->m_rtcp_addr;
		reverse->nt_dport = htons(mi->m_rtcp_port);
		break;
	default:
		npf_alg_tuple_free(forward);
		npf_alg_tuple_free(reverse);
		sip_tuple_data_put(td);
		return;
	}

	sip_tuple_data_get(td);

	rc = npf_alg_tuple_add_replace(sip_alg_instance(sip), forward);
	if (rc) {
		npf_alg_tuple_free(forward);
		npf_alg_tuple_free(reverse);
		sip_tuple_data_put(td);
		return;
	}

	/* Now deal with the reverse tuple */
	npf_alg_tuple_pair(forward, reverse);
	sip_tuple_data_get(td);
	reverse->nt_alg_flags |= SIP_ALG_REVERSE;

	rc = npf_alg_tuple_add_replace(sip_alg_instance(sip), reverse);
	if (rc) {
		npf_alg_tuple_unpair(reverse);
		npf_alg_tuple_expire(forward);
		npf_alg_tuple_free(reverse);
		sip_tuple_data_put(td);
	}
}

/*
 * sip_alg_create_rtp_tuples() - Create the RTP or UDP tuples.  Note that this
 *			traffic is di-directional, so we need to create
 *			one for each possible direction.
 */
static int sip_alg_create_rtp_tuples(npf_session_t *se,
				     const struct npf_alg *sip,
		struct sip_alg_request *sr, struct sip_alg_media *mi,
		struct sip_alg_media *mr)
{
	struct sip_tuple_data *td = NULL;
	int rc;
	struct npf_alg_tuple *forward;
	struct npf_alg_tuple *reverse;

	/* Allocate a pair of tuples */
	if (sip_alloc_tuple_pair(&forward, &reverse)) {
		sip_media_free(mi);
		sip_media_free(mr);
		return -ENOMEM;
	}

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
		npf_alg_tuple_free(forward);
		npf_alg_tuple_free(reverse);
		return -ENOMEM;
	}

	/* Common init */
	sip_alg_tuple_init(forward, se, td, mi->m_rtp_alen);
	sip_alg_tuple_init(reverse, se, td, mi->m_rtp_alen);
	forward->nt_alg_flags = SIP_ALG_RTP_FLOW;
	reverse->nt_alg_flags = SIP_ALG_RTP_FLOW;

	/* Set ports/addrs/flags */
	switch (td_nat_type(td)) {
	case sip_nat_snat:
		forward->nt_alg_flags |= SIP_ALG_NAT;
		forward->nt_sport = htons(mi->m_rtp_port);
		forward->nt_srcip = mi->m_rtp_addr;
		forward->nt_dport = htons(mr->m_rtp_port);
		forward->nt_dstip = mr->m_rtp_addr;

		reverse->nt_alg_flags |= SIP_ALG_NAT;
		reverse->nt_sport = htons(mr->m_trtp_port);
		reverse->nt_srcip = mr->m_trtp_addr;
		reverse->nt_dport = htons(mi->m_trtp_port);
		reverse->nt_dstip = mi->m_trtp_addr;
		break;
	case sip_nat_dnat:
		forward->nt_alg_flags |= SIP_ALG_NAT;
		forward->nt_sport = htons(mi->m_rtp_port);
		forward->nt_srcip = mi->m_rtp_addr;
		forward->nt_dport = htons(mr->m_rtp_port);
		forward->nt_dstip = mr->m_rtp_addr;

		reverse->nt_alg_flags |= SIP_ALG_NAT;
		reverse->nt_sport = htons(mr->m_trtp_port);
		reverse->nt_srcip = mr->m_trtp_addr;
		reverse->nt_dport = htons(mi->m_rtp_port);
		reverse->nt_dstip = mi->m_rtp_addr;
		break;
	case sip_nat_inspect:
		forward->nt_sport = htons(mi->m_rtp_port);
		forward->nt_srcip = mi->m_rtp_addr;
		forward->nt_dport = htons(mr->m_rtp_port);
		forward->nt_dstip = mr->m_rtp_addr;

		reverse->nt_sport = htons(mr->m_rtp_port);
		reverse->nt_srcip = mr->m_rtp_addr;
		reverse->nt_dport = htons(mi->m_rtp_port);
		reverse->nt_dstip = mi->m_rtp_addr;
		break;
	default:
		sip_tuple_data_put(td);
		npf_alg_tuple_free(forward);
		npf_alg_tuple_free(reverse);
		return -EINVAL;
	}

	rc = npf_alg_tuple_add_replace(sip_alg_instance(sip), forward);
	if (rc) {
		sip_tuple_data_put(td);
		npf_alg_tuple_free(forward);
		npf_alg_tuple_free(reverse);
		return rc;
	}

	/* Now deal with the reverse tuple */
	npf_alg_tuple_pair(forward, reverse);
	sip_tuple_data_get(td);
	reverse->nt_alg_flags |= SIP_ALG_REVERSE;

	rc = npf_alg_tuple_add_replace(sip_alg_instance(sip), reverse);
	if (rc) {
		sip_tuple_data_put(td);
		npf_alg_tuple_unpair(reverse);
		npf_alg_tuple_expire(forward);
		npf_alg_tuple_free(reverse);
	}

	return rc;
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
	const struct npf_alg *sip = npf_alg_session_get_alg(se);
	int size = sip_media_count(&invite->sr_media);

	/*
	 * If the invite and response port lists are different sizes,
	 * then we had a bad SDP packet in either - They must be the
	 * same size.
	 */
	if (size != sip_media_count(&response->sr_media))
		return -1;

	/*
	 * Prepare for creating tuples out of each media definition
	 * from the invite and response.
	 */
	for (pos = 0; pos < size; pos++) {
		struct sip_alg_media  *i;
		struct sip_alg_media  *r;

		i = cds_list_first_entry(&invite->sr_media,
					struct sip_alg_media, m_list);
		cds_list_del(&i->m_list);

		r = cds_list_first_entry(&response->sr_media,
					struct sip_alg_media, m_list);
		cds_list_del(&r->m_list);

		/* This consumes the medias */
		rc = sip_alg_create_rtp_tuples(se, sip, invite, i, r);
		if (rc)
			break;
	}

	return rc;
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
 * Add the call id on the session handle private data.
 * We will expire these then the session handle is expired.
 *
 * Note this is non-fatal if we cannot add it.  All it means is
 * that the INVITES will timeout/expire.
 */
static void sip_alg_add_session_call_id(npf_session_t *se,
		struct sip_alg_request *sr)
{
	osip_call_id_t *cid;
	struct sip_alg_session *ss;
	int i;
	size_t sz;

	/* Only CNTL sessions have private data */
	ss = npf_alg_session_get_private(se);
	if (!ss)
		return;

	cid = osip_message_get_call_id(sr->sr_sip);
	if (!cid)
		return;

	/* Only add unique, ignore re-transmissions... */
	for (i = 0; i < ss->ss_call_id_count; i++) {
		if (osip_call_id_match(cid, ss->ss_call_ids[i])
							== OSIP_SUCCESS)
			return;
	}

	sz = sizeof(osip_call_id_t *) * (ss->ss_call_id_count + 1);
	ss->ss_call_ids = realloc(ss->ss_call_ids, sz);
	if (!ss->ss_call_ids)
		return;
	if (osip_call_id_clone(cid, &ss->ss_call_ids[ss->ss_call_id_count]) !=
			OSIP_SUCCESS)
		return;
	ss->ss_call_id_count++;
	return;
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
 * Manage all SIP requests.  If appropriate, add
 * an INVITE to the sip hash table.
 *
 * Note that all call-ids for INVITEs are added to the
 * CNTL session handle, and are expired (if they exist)
 * when the session handle is expired.
 *
 * We will also add the ALT CNTL tuple in here, but only
 * once.
 */
static int sip_manage_request(npf_session_t *se,
		npf_cache_t *npc,
		struct sip_alg_request *sr,
		struct sip_alg_request *tsr,
		npf_nat_t *nat, bool *consumed)
{
	const struct npf_alg *sip = npf_alg_session_get_alg(se);
	int rc;

	/* Set per-packet info */
	npc->npc_alg_flags = SIP_NPC_REQUEST;

	if (MSG_IS_CANCEL(tsr->sr_sip) || MSG_IS_BYE(tsr->sr_sip)) {
		sip_request_lookup_and_expire(sip, tsr);
		return 0;
	}

	/*
	 * Get the reply path from the VIA header, must be present.  Note that
	 * this call returns an error for Requests in the reverse direction,
	 * hence we handle the CANCEL and BYE Requests above.
	 */
	rc = sip_parse_reply_path(sr, se);
	if (rc)
		return rc;

	/* This will only add the alt cntl tuple once */
	rc = sip_alg_manage_cntl(se, npc, tsr);
	if (rc)
		return rc;

	/* Either parse and add the INVITE, or handle a BYE/etc */
	if (MSG_IS_INVITE(tsr->sr_sip)) {
		if (!sr->sr_sdp)
			return -EINVAL;

		rc = sip_alg_manage_media(se, nat, tsr);
		if (rc)
			return rc;

		rc = sip_alg_add_invite(sip, tsr);
		if (!rc) {
			sip_alg_add_session_call_id(se, tsr);
			*consumed = true;
		}

	}

	return rc;
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
static int sip_manage_response(npf_session_t *se, npf_cache_t *npc,
		struct sip_alg_request *sr, struct sip_alg_request *tsr,
		npf_nat_t *nat)

{
	struct sip_alg_request *osr;
	const struct npf_alg *sip = npf_alg_session_get_alg(se);
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

/*
 * sip_alg_manage_sip()	- Manage the SIP message.
 *			Used both both nat and inspect.
 */
static int sip_alg_manage_sip(npf_session_t *se, npf_cache_t *npc,
		struct sip_alg_request *sr, struct sip_alg_request *tsr,
		npf_nat_t *nat, bool *consumed)
{
	int rc = -EINVAL;

	/*
	 * Handle (thus far) valid requests and responses,
	 * all garbage will result in a drop packet.
	 */
	if (MSG_IS_REQUEST(tsr->sr_sip))
		rc = sip_manage_request(se, npc, sr, tsr, nat, consumed);
	else if (MSG_IS_RESPONSE(tsr->sr_sip))
		rc = sip_manage_response(se, npc, sr, tsr, nat);

	return rc;
}

/*
 * sip_alg_manage_packet() - manage and translate SIP packets
 */
static int sip_alg_manage_packet(npf_session_t *se, struct sip_alg_request *sr,
			npf_cache_t *npc, struct rte_mbuf *nbuf, npf_nat_t *nat)
{
	struct sip_alg_request *tsr = NULL;
	const struct npf_alg *sip = npf_alg_session_get_alg(se);
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
 * sip_init_nat() - Init the 'nat' params for this request
 */
static void sip_init_nat(struct sip_alg_request *sr, bool forw,
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
 * sip_alg_translate_packet()
 */
static int sip_alg_translate_packet(npf_session_t *se, npf_cache_t *npc,
			npf_nat_t *ns, struct rte_mbuf *nbuf, const int di)
{
	npf_addr_t taddr;
	const struct npf_alg *sip = npf_alg_session_get_alg(se);
	in_port_t tport;
	npf_addr_t oaddr;
	in_port_t oport;
	bool forw;
	struct sip_alg_request *sr;

	/* Don't manipulate (TCP) packets w/o data */
	if (!npf_payload_len(npc))
		return 0;

       /*
	* Parsed msg may have been placed into session provate data by tuple
	* inspect
	*/
	sr = sip_alg_parse(sip, npc, npf_session_get_if_index(se), nbuf);
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

/*
 * sip_alg_inspect_packet() - Prep for packet inspection
 */
static void sip_alg_inspect_packet(npf_session_t *se, npf_cache_t *npc,
				struct rte_mbuf *nbuf, int di)
{
	struct sip_alg_request *sr;
	const struct npf_alg *sip = npf_alg_session_get_alg(se);
	bool consumed = false;

	sr = sip_alg_parse(sip, npc, npf_session_get_if_index(se), nbuf);
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
 * sip_translate_reply_path()
 */
static void sip_translate_reply_path(npf_session_t *se, int di __unused,
		struct rte_mbuf *nbuf, npf_cache_t *npc)
{
	/*
	 * We *dont* want to rewrite the dest IP address until VRVDR-31954 is
	 * resolved.
	 *
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
	 * While most SIP implementations set the VIA to match
	 * the port/addr of the initiator, the SIP RFC states that
	 * reply packets must be routed to the addr/port in the VIA.
	 *
	 * Newer Cisco phones implement the RFC exactly.  They use a
	 * high numbered sport for sending out msgs and expect
	 * reply packets on the default SIP port (5060).
	 *
	 * The situation we have here, according to the RFC is:
	 *
	 *		a1:p1	-->	a2:p2
	 *		a3:p3	<--
	 *
	 *   But this screws up our session handles, which were added to
	 *   a1:p1 - a2:p2, so we need to do this translation outside
	 *   of the nat engine to maintain a sane view of session
	 *   handles (as well as return the reply appropriately.
	 *
	 *   Only do this for UDP.
	 */


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
	if (!npf_v4_rwrcksums(npc, nbuf, n_ptr, l3_delta, l4_delta))
		return;

	/* Now translate */
	if (!npf_rwrip(npc, nbuf, n_ptr, PFIL_IN, &ss->ss_via_addr))
		return;

	/* Now the port */
	npf_rwrport(npc, nbuf, n_ptr, PFIL_IN, ss->ss_via_port);
}

/*
 * sip_alg_inspect() - Inspect non-natted flow
 */
static void sip_alg_inspect(npf_session_t *se, npf_cache_t *npc,
		struct rte_mbuf *nbuf, struct ifnet *ifp __unused,
		int di)
{
	uint32_t flags = npf_alg_session_get_flags(se);

	/* sanity - can only be CNTL flow  */
	if (!(flags & (SIP_ALG_CNTL_FLOW | SIP_ALG_ALT_CNTL_FLOW)))
		return;

	if (npf_iscached(npc, NPC_IP4))
		sip_translate_reply_path(se, di, nbuf, npc);

	if (!npf_iscached(npc, NPC_NATTED))
		sip_alg_inspect_packet(se, npc, nbuf, di);
}

/* sip_alg_natout() - packet NAT (SNAT) out*/
static int sip_alg_nat_out(npf_session_t *se, npf_cache_t *npc,
		struct rte_mbuf *nbuf, npf_nat_t *ns)
{
	/* This can only be the SIP flow */
	return sip_alg_translate_packet(se, npc, ns, nbuf, PFIL_OUT);
}

/* sip_alg_nat_in() - Packet NAT in */
static int sip_alg_nat_in(npf_session_t *se, npf_cache_t *npc,
		struct rte_mbuf *nbuf, npf_nat_t *ns)
{
	/* This can only be the SIP flow */
	return sip_alg_translate_packet(se, npc, ns, nbuf, PFIL_IN);
}

/* sip_alg_session_destroy() - session handle destroy */
static void sip_alg_session_destroy(npf_session_t *se)
{
	/* Only the reply datum for cntl */
	if (npf_alg_session_test_flag(se, SIP_ALG_CNTL_FLOW))
		sip_alg_private_session_free(se);
}

/* sip_alg_session_expire() - session handle expire */
static void sip_alg_session_expire(npf_session_t *se)
{
	if (npf_alg_session_test_flag(se, SIP_ALG_CNTL_FLOW))
		sip_expire_session_request(se);
}

/*
 * sip_alg_nat_inspect() - Inspect and assign the nat struct.
 */
static void sip_alg_nat_inspect(npf_session_t *se, npf_cache_t *npc __unused,
				npf_nat_t *nt, int di __unused)
{
	if (npf_alg_session_test_flag(se, SIP_ALG_CNTL_FLOW |
				      SIP_ALG_ALT_CNTL_FLOW))
		npf_nat_setalg(nt, npf_alg_session_get_alg(se));
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

static int sip_session_nat_media(npf_session_t *se, npf_cache_t *npc,
				 const int di, struct npf_alg_tuple *nt)
{
	struct sip_tuple_data *td = nt->nt_data;
	struct sip_alg_media *m = NULL;
	uint32_t nat_flags = 0;
	int rc;

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
	if (!(nt->nt_alg_flags & SIP_ALG_NAT) || !td)
		return 0;

	/* We may have to reverse the nat */
	if (nt->nt_alg_flags & SIP_ALG_REVERSE)
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

	switch (nt->nt_alg_flags & SIP_ALG_MASK) {
	case SIP_ALG_RTP_FLOW:
		nt->nt_nat = sip_create_nat(vrfid, nat_flags,
				m->m_rtp_reserved,
				m->m_rtp_addr, htons(m->m_rtp_port),
				m->m_trtp_addr, htons(m->m_trtp_port));
		if (nt->nt_nat) {
			rc = npf_alg_session_nat(se,
					npf_alg_parent_nat(nt->nt_se),
					npc, di, nt);
			if (!rc)
				m->m_rtp_reserved = false;
		}
		break;
	case SIP_ALG_RTCP_FLOW:
		nt->nt_nat = sip_create_nat(vrfid, nat_flags,
				m->m_rtcp_reserved,
				m->m_rtcp_addr, htons(m->m_rtcp_port),
				m->m_trtcp_addr, htons(m->m_trtcp_port));
		if (nt->nt_nat) {
			rc = npf_alg_session_nat(se,
					npf_alg_parent_nat(nt->nt_se),
					npc, di, nt);
			if (!rc)
				m->m_rtcp_reserved = false;
		}
		break;
	default:
		return -EINVAL;
	}

	return rc;
}

/*
 * Setup NAT for the alt control session.
 */
static int sip_session_nat_alt_cntl(npf_session_t *se, npf_cache_t *npc,
				    const int di, struct npf_alg_tuple *nt)
{
	npf_session_t *parent = nt->nt_se;
	npf_nat_t *pnat = npf_session_get_nat(parent);
	npf_addr_t oaddr;
	npf_addr_t taddr;
	in_port_t oport, tport;
	int ntype;
	uint masq;
	struct npf_alg_tuple dummy;
	int rc;

	/* Only if parent is natted */
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

	dummy.nt_nat = sip_create_nat(npf_session_get_vrfid(se),
				      NPF_NAT_REVERSE, false, oaddr, oport,
				      taddr, tport);
	if (!dummy.nt_nat)
		return -ENOMEM;

	rc = npf_alg_session_nat(se, pnat, npc, di, &dummy);
	if (!rc)
		npf_nat_setalg(npf_session_get_nat(se), nt->nt_alg);

	return rc;
}

static int sip_alg_session_init(npf_session_t *se, npf_cache_t *npc,
		struct npf_alg_tuple *nt, const int di)
{
	int rc = 0;

	npf_alg_session_set_flag(se, nt->nt_alg_flags);

	switch (nt->nt_alg_flags & SIP_ALG_MASK) {
	case SIP_ALG_CNTL_FLOW:
		npf_alg_session_set_inspect(se, true);
		rc = sip_alg_private_session_init(se);
		break;

	case SIP_ALG_ALT_CNTL_FLOW:
		npf_alg_session_set_inspect(se, true);
		npf_alg_session_set_flag(se, SIP_ALG_REVERSE);
		rc = sip_session_nat_alt_cntl(se, npc, di, nt);
		if (!rc)
			npf_session_link_child(nt->nt_se, se);
		break;

	case SIP_ALG_RTP_FLOW:
		rc = sip_session_nat_media(se, npc, di, nt);
		if (!rc) {
			struct sip_tuple_data *td = nt->nt_data;

			sip_alg_create_rtcp_tuples(se, npc, td);
			npf_session_link_child(nt->nt_se, se);
		}
		break;

	case SIP_ALG_RTCP_FLOW:
		rc = sip_session_nat_media(se, npc, di, nt);
		if (!rc)
			npf_session_link_child(nt->nt_se, se);
		break;
	}

	return rc;
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
	if (strcmp(argv[0], "port"))
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

static void sip_alg_periodic(struct npf_alg *sip)
{
	sip_ht_gc(sip);
}

/* alg struct */
static const struct npf_alg_ops sip_ops = {
	.name		= NPF_ALG_SIP_NAME,
	.se_init	= sip_alg_session_init,
	.se_destroy	= sip_alg_session_destroy,
	.se_expire	= sip_alg_session_expire,
	.inspect	= sip_alg_inspect,
	.config		= sip_alg_config,
	.nat_inspect	= sip_alg_nat_inspect,
	.nat_in		= sip_alg_nat_in,
	.nat_out	= sip_alg_nat_out,
	.periodic	= sip_alg_periodic,
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

	sp->sp_ht = cds_lfht_new(SIP_HT_INIT, SIP_HT_MIN, SIP_HT_MAX,
			CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);
	if (!sp->sp_ht)
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

static void sip_destroy_ht(struct npf_alg *sip)
{
	struct cds_lfht_iter iter;
	struct sip_alg_request *sr;
	struct sip_private *sp = sip->na_private;
	int rc;

	if (!sp)
		return;

	/*
	 * Free each request synchronously - ensures we
	 * sync return APM mappings prior tp APM instance destroy
	 */
	cds_lfht_for_each_entry(sp->sp_ht, &iter, sr, sr_node) {
		if (!cds_lfht_del(sp->sp_ht, &sr->sr_node))
			sip_alg_request_free_sync(sip, sr);
	}

	rcu_read_unlock();
	rc = cds_lfht_destroy(sp->sp_ht, NULL);
	rcu_read_lock();
	if (rc)
		RTE_LOG(ERR, FIREWALL, "ALG: SIP cds_lfht_destroy\n");

	/* Destroy any dead media added during ht destroy */
	sip_free_dead_media(sp);
}

/*
 * Destroy - we are guaranteed no access and a rcu quiesce period has
 * passed.
 */
void npf_alg_sip_destroy_instance(struct npf_alg *sip)
{
	if (sip) {
		sip_destroy_ht(sip);
		free(sip->na_private);
		sip->na_private = NULL;
		sip->na_enabled = false;
		sip->na_ai = NULL;

		/* Release reference on an alg application instance */
		npf_alg_put(sip);
	}
}

/* Constructor for one-time libosip initialization */
static void npf_alg_sip_init(void) __attribute__ ((__constructor__));

static void npf_alg_sip_init(void)
{
	osip_init(&sip_osip);
}
