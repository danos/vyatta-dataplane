/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * Private header for SIP alg files.
 */

#ifndef _SIP_H_
#define _SIP_H_

#include <rte_atomic.h>
#include <urcu.h>
#include "json_writer.h"
#include "util.h"

#include "npf/alg/alg.h"
#include "npf/alg/sip/sip_osip.h"
#include "npf/alg/sip/sip_request.h"
#include "npf/alg/sip/sip_response.h"
#include "npf/alg/sip/sip_parse.h"
#include "npf/alg/sip/sip_translate.h"

/*
 * SIP private data.
 *
 * We manage Invites and responses by using a hash table.  New invites are
 * added to the table, and corresponding responses pull them from the hash
 * table.
 */
struct sip_private {
	struct cds_lfht		*sp_ht;
	rte_spinlock_t		sp_media_lock; /* For media */
	struct cds_list_head	sp_dead_media; /* for freeing media */
};

/*
 * Type of nat being performed.
 */
enum sip_nat_type {
	sip_nat_snat = 1,
	sip_nat_dnat,
	sip_nat_inspect
};

static inline const char *sip_nat_type_str(enum sip_nat_type type)
{
	switch (type) {
	case sip_nat_snat:
		return "SIP_NAT_SNAT";
	case sip_nat_dnat:
		return "SIP_NAT_DNAT";
	case sip_nat_inspect:
		return "SIP_NAT_INSPECT";
	};
	return "Unknown";
}

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

/*
 * SIP request struct
 *
 * Created when we parse a SIP request message.  sr_osip and sr_sdp are the
 * two fields that are initialized and populated by the osip parser.
 *
 * Two object of this type are typically passed around - sr and tsr.  sr is
 * the original request, and tsr is a copy of the original request but with
 * NAT translations applied.
 *
 * Stored in a hash table in sip_alg_private, which is on the ALG instance
 * private data, alg->alg_private.
 */
struct sip_alg_request {
	struct cds_lfht_node	sr_node;
	uint64_t		sr_timeout;
	osip_message_t		*sr_sip;
	sdp_message_t		*sr_sdp;
	struct sip_nat		sr_nat;
	uint32_t		sr_if_idx;
	struct cds_list_head	sr_media_list_head;	/* media list head */
	uint8_t			sr_flags;
	struct npf_alg		*sr_sip_alg;
	struct rcu_head		sr_rcu_head;
	/*
	 * Store session handle so that we can identify requests created by
	 * this session.
	 */
	struct npf_session	*sr_session;
};

/* sr_flags */
#define SIP_REQUEST_EXPIRED	0x1
#define SIP_REQUEST_REMOVING	0x2

/*
 * Struct for managing rtp translation data. Note these ports are maintained
 * in host order.
 *
 * There are multiple media parts in the SDP message of the Invite and
 * Response packets.  A list of media structures is stored in the respective
 * Invite and Response sip_alg_request structures.  The Invite request is
 * stored in the sip alg hash table until a matching Response is received.
 *
 * When an Invite request is matched to a Response request then the media
 * information is used to create tuples, and the sip_alg_media structures are
 * then stored in the tuple private data.
 *
 * A list of these structures is stored in sip_alg_request sr_media.
 */
struct sip_alg_media {
	/* node in sr_media_list or sp_dead_media list */
	struct cds_list_head	m_node;

	enum sdp_proto		m_proto;
	enum sip_nat_type	m_type;
	uint8_t			m_ip_prot;

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
 * SIP ALG session flags (sa_flags, struct npf_session_alg)
 *
 * Also used in tuple flags (at_client_flags, struct apt_tuple)
 *
 * Flags defining the types of SIP/media flows.  Note that a SIP media UDP
 * flow is handled as a RTP flow.
 *
 * Least significant byte indicates flow type, of which lower nibble is
 * control flow types and upper nibble is data flow types.
 */
#define SIP_ALG_CNTL_FLOW	0x0001
#define SIP_ALG_ALT_CNTL_FLOW	0x0002

#define SIP_ALG_RTP_FLOW	0x0010
#define SIP_ALG_RTCP_FLOW	0x0020

#define SIP_ALG_REVERSE		0x0100
#define SIP_ALG_NAT		0x0200
#define SIP_ALG_ALT_TUPLE_SET	0x0400

#define SIP_ALG_CNTL		(SIP_ALG_CNTL_FLOW | SIP_ALG_ALT_CNTL_FLOW)
#define SIP_ALG_DATA		(SIP_ALG_RTP_FLOW | SIP_ALG_RTCP_FLOW)

#define SIP_ALG_MASK		(SIP_ALG_CNTL | SIP_ALG_DATA)

/*
 * Struct for managing tuple data.  These are added to media (RTP and RTCP)
 * tuples.
 *
 * Note ports are in host format.
 */
struct sip_tuple_data {
	struct npf_alg		*td_sip;
	struct sip_nat		td_nat;
	struct sip_alg_media	*td_mi;
	struct sip_alg_media	*td_mr;
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


/* SIP per-packet flags. */
#define SIP_NPC_REQUEST		0x01
#define SIP_NPC_RESPONSE	0x02


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

void sip_addr_from_str(const char *saddr, npf_addr_t *addr, uint8_t *alen);

/* Convert an address to an (allocated) string */
char *sip_addr_to_str(npf_addr_t *a, uint8_t alen);

/* Convert a port to an (allocated) string */
char *sip_port_to_str(in_port_t n);

struct sip_alg_session *npf_alg_session_get_sip(
	struct npf_session *se);

int sip_alg_verify(struct sip_alg_request *sr);

int sip_alg_manage_sip(npf_session_t *se, npf_cache_t *npc,
		       struct sip_alg_request *sr,
		       struct sip_alg_request *tsr,
		       npf_nat_t *nat, bool *consumed);

#endif /* _SIP_H_ */
