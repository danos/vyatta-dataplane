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

#define SESSION_PACK_VERSION	      (0x0102)

enum pack_session_new {
	NPF_PACK_SESSION_NEW_FW = 1,
	NPF_PACK_SESSION_NEW_NAT,
	NPF_PACK_SESSION_NEW_NAT64,
	NPF_PACK_SESSION_NEW_NAT_NAT64,
} __attribute__ ((__packed__));

/*
 *  From 'struct session' (except stats)
 */
struct npf_pack_dp_session {
	uint64_t	pds_id;	/* for logging */
	uint32_t	pds_custom_timeout;
	uint32_t	pds_timeout;
	uint16_t	pds_flags;
	uint8_t		pds_protocol;
	uint8_t		pds_protocol_state;
	uint8_t		pds_gen_state;
	uint8_t		pds_fw:1;
	uint8_t		pds_snat:1;
	uint8_t		pds_dnat:1;
	uint8_t		pds_nat64:1;
	uint8_t		pds_nat46:1;
	uint8_t		pds_parent:1;
	uint8_t		pds_alg:1;
	uint8_t		pds_in:1;
	uint8_t		pds_out:1;
	uint8_t		pds_app:1;
	uint8_t		pds_pad[1];
} __attribute__ ((__packed__));

/*
 * Stats from dataplane session, 'struct session'.  These are separate from
 * 'struct npf_pack_dp_session' since they are periodically updated.
 */
struct npf_pack_dp_sess_stats {
	uint64_t	pdss_pkts_in;
	uint64_t	pdss_bytes_in;
	uint64_t	pdss_pkts_out;
	uint64_t	pdss_bytes_out;
} __attribute__ ((__packed__));

struct npf_pack_sentry_packet {
	struct sentry_packet	psp_forw;
	struct sentry_packet	psp_back;
	char			psp_ifname[IFNAMSIZ];
} __attribute__ ((__packed__));

/*
 * From npf_session_t
 */
struct npf_pack_npf_session {
	int		pns_flags;
	uint32_t	pns_fw_rule_hash;
	uint32_t	pns_rproc_rule_hash;
} __attribute__ ((__packed__));

/*
 * Packed npf_state_t
 */
struct npf_pack_session_state {
	struct npf_tcp_window	pst_tcp_win[2];
	union {
		enum tcp_session_state	pst_tcp_state;
		enum dp_session_state	pst_gen_state;
	};
	uint8_t			pst_pad[3];
} __attribute__ ((__packed__));

/*
 * Packed npf_nat_t
 */
struct npf_pack_nat {
	uint16_t		pnt_l3_chk;
	uint16_t		pnt_l4_chk;
	uint32_t		pnt_map_flags;
	uint32_t		pnt_rule_hash;
	uint32_t		pnt_taddr;
	uint32_t		pnt_oaddr;
	uint16_t		pnt_tport;
	uint16_t		pnt_oport;
} __attribute__ ((__packed__));

struct npf_pack_nat64 {
	uint32_t		pn64_rule_hash;
	int32_t			pn64_rproc_id;
	struct in6_addr		pn64_t_addr;
	uint32_t		pn64_map_flags;
	in_port_t		pn64_t_port;
	uint8_t			pn64_v6;
	uint8_t			pn64_linked;
} __attribute__ ((__packed__));

struct npf_pack_session_fw {
	struct npf_pack_dp_session	pds;
	struct npf_pack_sentry_packet	psp;
	struct npf_pack_npf_session	pns;
	struct npf_pack_session_state	pst;
	struct npf_pack_dp_sess_stats	stats;
} __attribute__ ((__packed__));

struct npf_pack_session_nat {
	struct npf_pack_dp_session	pds;
	struct npf_pack_sentry_packet	psp;
	struct npf_pack_npf_session	pns;
	struct npf_pack_session_state	pst;
	struct npf_pack_dp_sess_stats	stats;
	struct npf_pack_nat		pnt;
} __attribute__ ((__packed__));

struct npf_pack_session_nat64 {
	struct npf_pack_dp_session	pds;
	struct npf_pack_sentry_packet	psp;
	struct npf_pack_npf_session	pns;
	struct npf_pack_session_state	pst;
	struct npf_pack_dp_sess_stats	stats;
	struct npf_pack_nat64		pn64;
} __attribute__ ((__packed__));

struct npf_pack_session_nat_nat64 {
	struct npf_pack_dp_session	pds;
	struct npf_pack_sentry_packet	psp;
	struct npf_pack_npf_session	pns;
	struct npf_pack_session_state	pst;
	struct npf_pack_dp_sess_stats	stats;
	struct npf_pack_nat		pnt;
	struct npf_pack_nat64		pn64;
} __attribute__ ((__packed__));

struct npf_pack_message_hdr {
	uint32_t		pmh_len;
	uint16_t		pmh_version;
	uint8_t			pmh_flags;
	enum session_pack_type	pmh_type;
} __attribute__ ((__packed__));

static_assert(sizeof(struct npf_pack_message_hdr) == 8,
	      "sizeof npf_pack_message_hdr");

struct npf_pack_session_hdr {
	uint32_t		psh_len;
	enum pack_session_new	psh_type;
	uint8_t			psh_pad[3];
} __attribute__ ((__packed__));

static_assert(sizeof(struct npf_pack_session_hdr) == 8,
	      "sizeof npf_pack_session_hdr");

struct npf_pack_session_new {
	struct	npf_pack_session_hdr hdr;
	char	cs[NPF_PACK_NEW_NAT_NAT64_SESSION_SIZE];
} __attribute__ ((__packed__));

struct npf_pack_session_update {
	uint64_t			psu_se_id;	/* for UT */
	struct npf_pack_sentry_packet	psu_psp;
	struct npf_pack_session_state	psu_pst;
	struct npf_pack_dp_sess_stats	psu_stats;
	uint16_t			psu_se_feature_count;
	uint8_t				psu_pad[2];
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

struct npf_pack_dp_sess_stats *
npf_pack_get_session_stats(struct npf_pack_message *msg);

#endif	/* NPF_PACK_H */
