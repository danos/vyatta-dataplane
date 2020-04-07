/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef NPF_PACK_H
#define NPF_PACK_H

#include "dp_session.h"
#include "npf/npf_state.h"
#include "session/session.h"

#define NPF_PACK_NEW_FW_SESSION_SIZE	       \
	(sizeof(struct npf_pack_session_hdr) + \
	 sizeof(struct npf_pack_session_fw))

#define NPF_PACK_NEW_NAT_SESSION_SIZE	       \
	(sizeof(struct npf_pack_session_hdr) + \
	 sizeof(struct npf_pack_session_nat))
#define NPF_PACK_NEW_NAT64_SESSION_SIZE		\
	(sizeof(struct npf_pack_session_hdr) +	\
	 sizeof(struct npf_pack_session_nat64))

#define NPF_PACK_NEW_NAT_NAT64_SESSION_SIZE	      \
	(sizeof(struct npf_pack_session_hdr)  +	      \
	 sizeof(struct npf_pack_session_nat_nat64))

/* New session includes nat64 peer session */
#define NPF_PACK_NEW_SESSION_MAX_SIZE (2 * sizeof(struct npf_pack_session_new))
#define NPF_PACK_UPDATE_SESSION_SIZE  (sizeof(struct npf_pack_session_update))

#define NPF_PACK_MESSAGE_MAX_SIZE     NPF_PACK_NEW_SESSION_MAX_SIZE
#define NPF_PACK_MESSAGE_MIN_SIZE     (sizeof(struct npf_pack_message_hdr))

#define SESSION_PACK_VERSION	      (0x0100)

enum {
	NPF_PACK_SESSION_NEW_FW = 1,
	NPF_PACK_SESSION_NEW_NAT,
	NPF_PACK_SESSION_NEW_NAT64,
	NPF_PACK_SESSION_NEW_NAT_NAT64,
	NPF_PACK_SESSION_NEW_END,
};

struct npf_pack_dp_session {
	uint64_t	se_id;	/* for logging */
	uint16_t	se_flags;
	uint8_t		se_protocol;
	uint32_t	se_custom_timeout;
	uint32_t	se_timeout;
	uint64_t	se_etime;
	uint8_t		se_protocol_state;
	uint8_t		se_nat;
	uint8_t		se_nat64;
	uint8_t		se_nat46;
	uint8_t		se_parent;
} __attribute__ ((__packed__));

struct npf_pack_sentry {
	struct sentry_packet	sp_forw;
	struct sentry_packet	sp_back;
	char			ifname[IFNAMSIZ];
} __attribute__ ((__packed__));

struct npf_pack_npf_session {
	int		s_flags;
	uint32_t	s_fw_rule_hash;
	uint32_t	s_rproc_rule_hash;
} __attribute__ ((__packed__));

struct npf_pack_npf_tcpstate {
	npf_tcpstate_t	nst_tcpst;
	uint8_t		pad[3];
} __attribute__ ((__packed__));

struct npf_pack_npf_state {
	struct npf_pack_npf_tcpstate	nst_tcpst[2];
	uint8_t				nst_state;
	uint8_t				pad[3];
} __attribute__ ((__packed__));

struct npf_pack_session_stats {
	uint64_t	se_pkts_in;
	uint64_t	se_bytes_in;
	uint64_t	se_pkts_out;
	uint64_t	se_bytes_out;
} __attribute__ ((__packed__));

struct npf_pack_npf_nat {
	uint16_t		nt_l3_chk;
	uint16_t		nt_l4_chk;
	uint32_t		nt_map_flags;
	uint32_t		nt_rule_hash;
	uint32_t		nt_taddr;
	uint32_t		nt_oaddr;
	uint16_t		nt_tport;
	uint16_t		nt_oport;
} __attribute__ ((__packed__));

struct npf_pack_npf_nat64 {
	uint32_t		n64_rule_hash;
	int			n64_rproc_id;
	uint32_t		n64_map_flags;
	struct in6_addr		n64_t_addr;
	in_port_t		n64_t_port;
	uint8_t			n64_v6;
	uint8_t			n64_linked;
	uint8_t			n64_has_np;
	uint8_t			pad[3];
} __attribute__ ((__packed__));

struct npf_pack_session_fw {
	struct npf_pack_dp_session	dps;
	struct npf_pack_sentry		sen;
	struct npf_pack_npf_session	se;
	struct npf_pack_npf_state	state;
	struct npf_pack_session_stats	stats;
} __attribute__ ((__packed__));

struct npf_pack_session_nat {
	struct npf_pack_dp_session	dps;
	struct npf_pack_sentry		sen;
	struct npf_pack_npf_session	se;
	struct npf_pack_npf_state	state;
	struct npf_pack_session_stats	stats;
	struct npf_pack_npf_nat		nt;
} __attribute__ ((__packed__));

struct npf_pack_session_nat64 {
	struct npf_pack_dp_session	dps;
	struct npf_pack_sentry		sen;
	struct npf_pack_npf_session	se;
	struct npf_pack_npf_state	state;
	struct npf_pack_session_stats	stats;
	struct npf_pack_npf_nat64	n64;
} __attribute__ ((__packed__));

struct npf_pack_session_nat_nat64 {
	struct npf_pack_dp_session	dps;
	struct npf_pack_sentry		sen;
	struct npf_pack_npf_session	se;
	struct npf_pack_npf_state	state;
	struct npf_pack_session_stats	stats;
	struct npf_pack_npf_nat		nt;
	struct npf_pack_npf_nat64	n64;
} __attribute__ ((__packed__));

struct npf_pack_message_hdr {
	uint32_t	len;
	uint16_t	version;
	uint8_t		flags;
	uint8_t		msg_type;
} __attribute__ ((__packed__));

struct npf_pack_session_hdr {
	uint32_t	len;
	uint8_t		msg_type;
	uint8_t		pad[3];
} __attribute__ ((__packed__));

struct npf_pack_session_new {
	struct	npf_pack_session_hdr hdr;
	char	cs[NPF_PACK_NEW_NAT_NAT64_SESSION_SIZE];
} __attribute__ ((__packed__));

struct npf_pack_session_update {
	uint64_t			se_id;	/* for UT */
	struct npf_pack_sentry		sen;
	struct npf_pack_npf_state	state;
	struct npf_pack_session_stats	stats;
	uint16_t			se_feature_count;
	uint8_t				pad[2];
} __attribute__ ((__packed__));

struct npf_pack_message {
	struct		npf_pack_message_hdr hdr;
	union {
		char	cs_new[NPF_PACK_NEW_SESSION_MAX_SIZE];
		struct	npf_pack_session_update cs_update;
	} data;
} __attribute__ ((__packed__));

bool npf_pack_validate_msg(struct npf_pack_message *msg, uint32_t size);
uint8_t npf_pack_get_msg_type(struct npf_pack_message *msg);
uint64_t npf_pack_get_session_id(struct npf_pack_message *msg);

struct npf_pack_session_stats *
npf_pack_get_session_stats(struct npf_pack_message *msg);

#endif	/* NPF_PACK_H */
