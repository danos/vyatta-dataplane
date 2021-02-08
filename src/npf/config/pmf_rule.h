/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _PMF_RULE_H_
#define _PMF_RULE_H_

#include <stdint.h>
#include <stdbool.h>

/*
 * NB: None byte sized fields are in native endian order.
 */

enum pmf_l2_field {
	PMF_L2F_ETH_SRC	= 1,
	PMF_L2F_ETH_DST,
	PMF_L2F_ETH_TYPE,
	PMF_L2F_ETH_PCP,
	PMF_L2F_IP_FAMILY,	/* Could infer / encode from prefix */
	PMF_L2F__LEN
};

enum pmf_l3_field {
	PMF_L3F_SRC	= 1,
	PMF_L3F_DST,
	PMF_L3F_PROTO,
	PMF_L3F_PROTOF,
	PMF_L3F_PROTOB,
	PMF_L3F_DSCP,
	PMF_L3F_TTL,
	PMF_L3F_FRAG,		/* For IPv6 implies a header walk */
	PMF_L3F_RH,		/* Implies a header walk */
	PMF_L3F__LEN
};

enum pmf_l4_field {
	PMF_L4F_SRC	= 1,
	PMF_L4F_DST,
	PMF_L4F_TCP_FLAGS,
	PMF_L4F_ICMP_VALS,	/* type/code fields */
	PMF_L4F__LEN
};

enum pmf_mtag {
	PMAT_ETH_MAC	= 1,
	PMAT_ETH_TYPE,
	PMAT_ETH_PCP,
	PMAT_IP_FAMILY,

	PMAT_IPV4_PREFIX,
	PMAT_IPV6_PREFIX,
	PMAT_IPV4_RANGE,
	PMAT_IP_PROTO,
	PMAT_IP_DSCP,
	PMAT_IP_TTL,
	PMAT_IP_FRAG,
	PMAT_IPV6_RH,

	PMAT_L4_PORT_RANGE,
	PMAT_L4_TCP_FLAGS,
	PMAT_L4_ICMP_V4_VALS,
	PMAT_L4_ICMP_V6_VALS,

	PMAT_GROUP_REF,
	PMAT_IP_ADDR_GROUP,		/* Table of IPv4 and/or IPv6 addrs */
	PMAT_IP_PROTO_GROUP,
	PMAT_IP_DSCP_GROUP,
	PMAT_L4_PORT_GROUP,
	PMAT_L4_ICMP_V4_GROUP,
	PMAT_L4_ICMP_V6_GROUP,

	PMAT_MEXTENSION,
	PMAT_HEXTENSION,
	PMAT_AEXTENSION,

	PMAT_RPROC_RAW,
};

enum pmf_value {
	PMV_UNSET = 0,
	PMV_TRUE,
	PMV_FALSE,
};

enum pmf_nat_type {
	PMN_UNSET,
	PMN_SNAT,
	PMN_DNAT,
};

/* NAT port allocation */
enum pmf_nat_pa {
	PMPA_UNSET,
	PMPA_RAND,
	PMPA_SEQ,
};

enum pmf_mark_colour {
	PMMC_UNSET,
	PMMC_RED,
	PMMC_YELLOW,
	PMMC_GREEN,
};

/*
 * NB: Each attribute is malloc'ed individually, and so may be free'ed
 *     or easily duplicated.  They are either fixed size, or contain
 *     enough information to calculate the extra data allocated.
 *
 *     The same applies to the rproc fields/attributes below.
 */
struct pmf_attr_any {
	enum pmf_mtag	pm_tag : 8;
};

/*
 * This is an indirection object to reference the named resource group.
 * As such all are essentially the same, with just the type of the
 * referenced group differing.  Used with ref values of:
 *
 * PMAT_IP_ADDR_GROUP, PMAT_IP_PROTO_GROUP,   PMAT_IP_DSCP_GROUP,
 * PMAT_L4_PORT_GROUP, PMAT_L4_ICMP_V4_GROUP, PMAT_L4_ICMP_V6_GROUP.
 */
struct pmf_attr_group_ref {
	enum pmf_mtag	pm_tag : 8;		/* PMAT_GROUP_REF */
	enum pmf_mtag	pm_ref : 8;		/* See comment above */
	uint8_t		pm_nlen;		/* name length */
	char		pm_name[];
};

struct pmf_attr_emac {
	enum pmf_mtag	pm_tag : 8;		/* PMAT_ETH_MAC */
	uint8_t		pm_emac[6];
};

struct pmf_attr_etype {
	enum pmf_mtag	pm_tag : 8;		/* PMAT_ETH_TYPE */
	uint16_t	pm_etype;
};

struct pmf_attr_epcp {
	enum pmf_mtag	pm_tag : 8;		/* PMAT_ETH_PCP */
	uint8_t		pm_pcp;			/* 3 bits */
};

struct pmf_attr_ip_family {
	enum pmf_mtag	pm_tag : 8;		/* PMAT_IP_FAMILY */
	bool		pm_v6;			/* IPv4 or IPv6 */
};

struct pmf_attr_v4_prefix {
	enum pmf_mtag	pm_tag : 8;		/* PMAT_IPV4_PREFIX */
	uint8_t		pm_plen;
	bool		pm_invert;		/* If don't match prefix */
	uint8_t		pm_bytes[4];
};

struct pmf_attr_v6_prefix {
	enum pmf_mtag	pm_tag : 8;		/* PMAT_IPV6_PREFIX */
	uint8_t		pm_plen;
	bool		pm_invert;		/* If don't match prefix */
	uint8_t		pm_bytes[16];
};

struct pmf_attr_v4_range {
	enum pmf_mtag	pm_tag : 8;		/* PMAT_IPV4_RANGE */
	uint8_t		pm_first[4];
	uint8_t		pm_last[4];
};

struct pmf_attr_proto {
	enum pmf_mtag	pm_tag : 8;		/* PMAT_IP_PROTO */
	uint8_t		pm_proto;
	uint8_t		pm_unknown : 1;
	uint8_t		pm_final : 1;
	uint8_t		pm_base : 1;
};

struct pmf_attr_dscp {
	enum pmf_mtag	pm_tag : 8;		/* PMAT_IP_DSCP */
	uint8_t		pm_dscp;		/* 6 bits */
};

struct pmf_attr_ttl {
	enum pmf_mtag	pm_tag : 8;		/* PMAT_IP_TTL */
	uint8_t		pm_ttl;
};

struct pmf_attr_frag {
	enum pmf_mtag	pm_tag : 8;		/* PMAT_IP_FRAG */
	/* Need something here for initial / non initial / not allowed */
};

struct pmf_attr_v6_rh {
	enum pmf_mtag	pm_tag : 8;		/* PMAT_IPV6_RH */
	uint8_t		pm_type;
};

struct pmf_attr_l4port_range {
	enum pmf_mtag	pm_tag : 8;		/* PMAT_L4_PORT_RANGE */
	uint16_t	pm_loport;
	uint16_t	pm_hiport;
};

struct pmf_attr_l4tcp_flags {
	enum pmf_mtag	pm_tag : 8;		/* PMAT_L4_TCP_FLAGS */
	uint16_t	pm_mask;		/* (flags & mask) == match */
	uint16_t	pm_match;		/* 12 bits */
};

struct pmf_attr_l4icmp_vals {
	enum pmf_mtag	pm_tag : 8;		/* _V4_VALS / _V6_VALS */
	uint8_t		pm_type;
	uint8_t		pm_code;
	bool		pm_any_code : 1;	/* if true, ignore code */
	bool		pm_class : 1;		/* if true, mask type */
	bool		pm_named : 1;		/* came from a string name */
};

/* All of the basic match attributes */

/* L2 stuff */
union pmf_mattr_l2 {
	struct pmf_attr_any		*pm_any;
	struct pmf_attr_emac		*pm_emac;
	struct pmf_attr_etype		*pm_etype;
	struct pmf_attr_epcp		*pm_epcp;
	struct pmf_attr_ip_family	*pm_ipfam;
};
/* L3 stuff */
union pmf_mattr_l3 {
	struct pmf_attr_any		*pm_any;
	struct pmf_attr_v4_prefix	*pm_l3v4;
	struct pmf_attr_v6_prefix	*pm_l3v6;
	struct pmf_attr_proto		*pm_l3proto;
	struct pmf_attr_dscp		*pm_l3dscp;
	struct pmf_attr_ttl		*pm_l3ttl;
	struct pmf_attr_frag		*pm_l3frag;
	struct pmf_attr_v6_rh		*pm_l3v6rh;
	struct pmf_attr_group_ref	*pm_l3group;
};
/* L4 stuff */
union pmf_mattr_l4 {
	struct pmf_attr_any		*pm_any;
	struct pmf_attr_l4port_range	*pm_l4port_range;
	struct pmf_attr_l4tcp_flags	*pm_l4tcp_flags;
	struct pmf_attr_l4icmp_vals	*pm_l4icmp_vals;
	struct pmf_attr_group_ref	*pm_l4group;
};

/* rproc (match/action/handle) attributes */

struct pmf_proc_any {
	enum pmf_mtag	pm_tag : 8;
};

#define PMP_RAW_ID_UNSET 255
struct pmf_proc_raw {
	enum pmf_mtag	pm_tag : 8;		/* PMAT_RPROC_RAW */
	uint8_t		pm_id;			/* unset or enum npf_rproc_id */
	uint16_t	pm_dlen;		/* length of data */
	uint8_t		pm_argoff;		/* within pm_name; 0: no args */
	char		pm_name[];		/* name, '\0', args */
};

union pmf_proc {
	char			*pp_str;	/* Only during initial parse */
	struct pmf_proc_any	*pp_any;
	struct pmf_proc_raw	*pp_raw;
};

/* List of part parsed rproc values.  e.g. "dpi(fred)" and/or "path_monitor" */
struct pmf_pext_list {
	enum pmf_mtag		pm_tag : 8;		/* M/A/H EXTENSION */
	uint8_t			pm_unknown;		/* num unknown rprocs */
	uint8_t			pm_num;			/* length of array */
	union pmf_proc		pm_procs[];
};

/*
 * The parsed result of a NAT rule.
 *
 * This will need later validation to ensure that pan_type is set,
 * and possibly set pan_pinhole to a default of FALSE.
 */
struct pmf_nat {
	enum pmf_nat_type		pan_type : 2;
	enum pmf_value			pan_pinhole : 2;
	enum pmf_value			pan_exclude : 2;
	enum pmf_value			pan_masquerade : 2;
	enum pmf_nat_pa			pan_port_alloc : 2;

	/* Following only valid for "nat-src" / "nat-dst" */
	union {
		struct pmf_attr_any		*any;
		struct pmf_attr_v4_range	*range;
		struct pmf_attr_group_ref	*group;
	} pan_taddr;
	struct pmf_attr_l4port_range	*pan_tports;
};

enum pmf_summary {
	PMF_RMS_ETH_SRC		= (1 <<  0),
	PMF_RMS_ETH_DST		= (1 <<  1),
	PMF_RMS_ETH_TYPE	= (1 <<  2),
	PMF_RMS_ETH_PCP		= (1 <<  3),
	PMF_RMS_IP_FAMILY	= (1 <<  4),
	/* L2 Spare */
	PMF_RMS_L3_SRC		= (1 <<  8),
	PMF_RMS_L3_DST		= (1 <<  9),
	PMF_RMS_L3_PROTO_BASE	= (1 << 10),
	PMF_RMS_L3_PROTO_FINAL	= (1 << 11),
	PMF_RMS_L3_DSCP		= (1 << 12),
	PMF_RMS_L3_FRAG		= (1 << 13),
	PMF_RMS_L3_RH		= (1 << 14),
	PMF_RMS_L3_TTL		= (1 << 15),
	/* L3 Spare */
	PMF_RMS_L4_SRC		= (1 << 16),
	PMF_RMS_L4_DST		= (1 << 17),
	PMF_RMS_L4_TCPFL	= (1 << 18),
	PMF_RMS_L4_ICMP_TYPE	= (1 << 19),
	PMF_RMS_L4_ICMP_CODE	= (1 << 20),
	/* L4 Spare */
	/* Actions follow */
	PMF_RAS_QOS_HW_DESIG	= (1 << 21),
	PMF_RAS_QOS_COLOUR	= (1 << 22),
	PMF_RAS_QOS_POLICE	= (1 << 23),
	PMF_RAS_DROP		= (1 << 24),
	PMF_RAS_PASS		= (1 << 25),
	PMF_RAS_COUNT_DEF	= (1 << 26),
	PMF_RAS_COUNT_REF	= (1 << 27),
	/* Action counters (auto-per-action) */
	PMF_RAS_COUNT_DEF_PASS	= (1 << 28),
	PMF_RAS_COUNT_DEF_DROP	= (1 << 29),
#define PMF_SUMMARY_COUNT_DEF_NAMED_FLAGS \
	(PMF_RAS_COUNT_DEF_PASS|PMF_RAS_COUNT_DEF_DROP)
};

/*
 * The parsed result of a QoS mark.
 */
struct pmf_qos_mark {
	enum pmf_value			paqm_has_desig: 2;

	uint8_t				paqm_desig : 3;
	enum pmf_mark_colour		paqm_colour : 3;
};

struct pmf_rule {
	struct {
		union pmf_mattr_l2	l2[PMF_L2F__LEN];
		union pmf_mattr_l3	l3[PMF_L3F__LEN];
		union pmf_mattr_l4	l4[PMF_L4F__LEN];
		struct pmf_pext_list	*extend;	/* "match" rprocs */
	} pp_match;
	struct {
		enum pmf_value		fate : 2;
		enum pmf_value		stateful : 2;
		struct pmf_nat		*nat;
		struct pmf_pext_list	*handle;	/* "handle" rprocs */
		struct pmf_pext_list	*extend;	/* action rprocs */
		struct pmf_qos_mark	*qos_mark;
		uintptr_t		qos_policer;	/* FAL object id */
	} pp_action;
	uint32_t pp_summary;
	uint32_t pp_refcnt;
};

void pmf_rule_extension_free(struct pmf_pext_list **ext_p);
void pmf_rule_free(struct pmf_rule *rule);
void *pmf_leaf_attr_copy(void *attr);
struct pmf_pext_list *pmf_pexts_attr_copy(struct pmf_pext_list *old_exts);
struct pmf_rule *pmf_rule_copy(struct pmf_rule *old_rule);

/* Create most dyanmic leaf attrs using pkp_leaf_attr_copy */

struct pmf_attr_v6_prefix *pmf_v6_prefix_create(bool invert, uint8_t plen,
						void *bytes);
struct pmf_attr_v4_prefix *pmf_v4_prefix_create(bool invert, uint8_t plen,
						void *bytes);
struct pmf_attr_group_ref *pmf_create_addr_group_ref(char const *name);
struct pmf_attr_group_ref *pmf_create_proto_group_ref(char const *name);
struct pmf_attr_group_ref *pmf_create_dscp_group_ref(char const *name);
struct pmf_attr_group_ref *pmf_create_port_group_ref(char const *name);
struct pmf_attr_group_ref *pmf_create_icmp_group_ref(char const *name,
							bool is_v6);

struct pmf_pext_list *pmf_rproc_mlist_create(uint32_t num);
struct pmf_pext_list *pmf_rproc_alist_create(uint32_t num);
struct pmf_pext_list *pmf_rproc_hlist_create(uint32_t num);

struct pmf_proc_raw *pmf_rproc_raw_create(uint32_t data_len, void *data);

struct pmf_nat *pmf_nat_create(void);
struct pmf_qos_mark *pmf_qos_mark_create(void);
struct pmf_rule *pmf_rule_alloc(void);

#endif /* _PMF_RULE_H_ */
