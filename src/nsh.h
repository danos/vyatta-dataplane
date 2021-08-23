/*
 * Copyright (c) 2017-2019,2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef NSH_H
#define NSH_H

#include <endian.h>
#include <rte_mbuf.h>
#include <stdint.h>
#include <sys/types.h>

#define NSH_V0        0

/* NSH Base Header Next Protocol */
enum nsh_np {
	NSH_NP_NONE  = 0,
	NSH_NP_IPv4  = 1,
	NSH_NP_IPv6  = 2,
	NSH_NP_ETHER = 3,
	NSH_NP_NSH   = 4,
	NSH_NP_MPLS  = 5,
	NSH_NP_MAX   = 6
};

#define NSH_MD_T1  1
#define NSH_MD_T2  2

/* NSH Base + Service Path Header */
/* Definitions as per draft-ietf-sfc-nsh-01 */
struct nsh {
	union {                               /* Base header */
		struct {
#if __BYTE_ORDER == __BIG_ENDIAN
			uint nsh_version:2;    /* NSH version */
			uint nsh_oam:1;        /* payload is OAM */
			uint nsh_critical:1;   /* critical metadata TLV */
			uint nsh_reserved:6;
			uint nsh_length:6;     /* NSH hdr len in 4 byte words */
			uint nsh_md_type:8;    /* metadata type */
			uint nsh_nxt_proto:8;  /* protocol type of payload */
#elif __BYTE_ORDER == __LITTLE_ENDIAN
			uint nsh_nxt_proto:8;
			uint nsh_md_type:8;
			uint nsh_length:6;
			uint nsh_reserved:6;
			uint nsh_critical:1;
			uint nsh_oam:1;
			uint nsh_version:2;
#else
# error	"Please include <bits/endian.h>"
#endif
		} bh_str;
		uint32_t bh;
	} bh_u;
	union {                               /* Service Path header */
		struct {
#if __BYTE_ORDER == __BIG_ENDIAN
			uint nsh_spi:24;       /* Service Path Index */
			uint nsh_si:8;         /* Service index */
#elif __BYTE_ORDER == __LITTLE_ENDIAN
			uint nsh_si:8;
			uint nsh_spi:24;
#else
# error	"Please include <bits/endian.h>"
#endif
		} sph_str;
		uint32_t sph;
	} sph_u;
} __attribute__ ((__packed__));

#define nsh_ver       bh_u.bh_str.nsh_version
#define nsh_oam       bh_u.bh_str.nsh_oam
#define nsh_crit      bh_u.bh_str.nsh_critical
#define nsh_len       bh_u.bh_str.nsh_length
#define nsh_mdtype    bh_u.bh_str.nsh_md_type
#define nsh_nxtproto  bh_u.bh_str.nsh_nxt_proto
#define nsh_spi       sph_u.sph_str.nsh_spi
#define nsh_si        sph_u.sph_str.nsh_si
#define nsh_bh        bh_u.bh_all
#define nsh_sph       sph_u.sph_all

/* NSH Metadata Type 1 hdr */
/* Data Center context allocation - draft-guichard-sfc-nsh-dc-allocation-02 */
struct nsh_md_t1 {
	union {
		struct {
#if __BYTE_ORDER == __BIG_ENDIAN
			uint dst_class_set:1;
			uint svc_tag_set:1;
			uint rsvd:2;
			uint src_node:12;
			uint src_intf:16;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
			uint src_intf:16;
			uint src_node:12;
			uint rsvd:2;
			uint svc_tag_set:1;
			uint dst_class_set:1;
#else
#endif
		} md1_w1;
		uint32_t md1_npc; /* Network Platform context */
	} u1;
	union {
		struct {
#if __BYTE_ORDER == __BIG_ENDIAN
			uint rsvd:8;
			uint tenant_id:24;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
			uint tenant_id:24;
			uint rsvd:8;
#else
#endif
		} md1_w2;
		uint32_t md1_nsc; /* Network Shared Context */
	} u2;
	union {
		struct {
#if __BYTE_ORDER == __BIG_ENDIAN
			uint16_t dst_class_rsvd;
			uint16_t src_class;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
			uint16_t src_class;
			uint16_t dst_class_rsvd;
#else
#endif
		} md1_w3;
		uint32_t md1_spc; /* Service Platform Context */
	} u3;
	union {
		struct {
#if __BYTE_ORDER == __BIG_ENDIAN
			uint ack:1;
			uint svc_tag:31;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
			uint svc_tag:31;
			uint ack:1;
#else
#endif
		} md1_w4;
		uint32_t md1_ssc; /* Service Shared Context */
	} u4;
} __attribute__ ((__packed__));

#define nsh_npc u1.md1_npc
#define nsh_nsc u2.md1_nsc
#define nsh_spc u3.md1_spc
#define nsh_ssc u4.md1_ssc

#define NSH_MD1_NUM_ATTRS 4

/* NSH Metadata Type 2 hdr */
struct nsh_md_t2 {
	union {
		struct {
#if __BYTE_ORDER == __BIG_ENDIAN
			uint     md2_tlv_class:16;
			uint     md2_critical:1;
			uint     md2_type:7;
			uint     md2_reserved:3;
			uint     md2_length:5;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
			uint     md2_length:5;
			uint     md2_reserved:3;
			uint     md2_type:7;
			uint     md2_critical:1;
			uint     md2_tlv_class:16;
#else
# error	"Please include <bits/endian.h>"
#endif
		} md_t2_str;
		uint32_t md_t2_hdr;
	} u;
} __attribute__ ((__packed__));

#define md2_tlvc   u.md_t2_str.md2_tlv_class
#define md2_crit   u.md_t2_str.md2_critical
#define md2_type   u.md_t2_str.md2_type
#define md2_rsvd   u.md_t2_str.md2_reserved
#define md2_len    u.md_t2_str.md2_length
#define md2_hdr    u.md_t2_hdr

/* Unit size used in NSH length */
#define NSH_LEN_UNIT  sizeof(uint32_t)

/* size of NSH with Type 1 Metadata */
#define NSH_T1_LEN     \
	((sizeof(struct nsh) + sizeof(struct nsh_md_t1)) / NSH_LEN_UNIT)

/* minimum length of NSH with Type 2 Metadata */
#define NSH_T2_MIN_LEN (sizeof(struct nsh) / NSH_LEN_UNIT)

struct nsh_tlv {
	int ntlv_class;
	int ntlv_type;
	uint16_t ntlv_len;
	void *ntlv_val;
};

/*
 * Parse hdr, return payload proto and pointer to payload */
int nsh_get_payload(struct nsh *nsh_start, enum nsh_np *nxtproto,
		    void **nsh_payload);

#endif /* NSH_H */
