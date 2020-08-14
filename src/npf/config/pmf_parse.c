/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>	/* For TH_xxx; the TCP header flags */

#include "compiler.h"
#include "util.h"
#include "vplane_log.h"

#include "pmf_rule.h"
#include "pmf_parse.h"
#include "npf/rproc/npf_rproc.h"

static char const empty_str[] = "";

/*
 * Note that this is really only match NPF rule groups, and whatever
 * they may contain. We have other uses of groups for resources, as below:
 *
 * resources {
 *        group {
 *                dscp-group DSCPs {
 *                        dscp 1
 *                        dscp 3
 *                        dscp 5
 *                        dscp 7
 *                        dscp af11
 *                }
 *                icmp-group ICMPv4 {
 *                        name echo-reply
 *                        name echo-request
 *                        type 4
 *                        type 5 {
 *                                code 7
 *                        }
 *                }
 *                icmpv6-group ICMPv6 {
 *                        name echo-reply
 *                        name echo-request
 *                        type 6 {
 *                                code 9
 *                        }
 *                }
 *                port-group Ports {
 *                        port 2-17
 *                        port 4
 *                        port 9
 *                        port ssh
 *                }
 *                protocol-group Prots {
 *                        protocol tcp
 *                        protocol udp
 *                }
 *        }
 * }
 *
 * Which results in commands as below:
 *
 *  npf-cfg delete protocol-group:Prots
 *  npf-cfg add protocol-group:Prots 0 6;17
 *  npf-cfg commit
 *  npf-cfg delete dscp-group:DSCPs
 *  npf-cfg add dscp-group:DSCPs 0 1;3;5;7;10
 *  npf-cfg commit
 *  npf-cfg delete icmp-group:ICMPv4
 *  npf-cfg add icmp-group:ICMPv4 0 echo-reply;echo-request;4;5:7
 *  npf-cfg commit
 *  npf-cfg delete icmpv6-group:ICMPv6
 *  npf-cfg add icmpv6-group:ICMPv6 0 echo-reply;echo-request;6:9
 *  npf-cfg commit
 *  npf-cfg delete port-group:Ports
 *  npf-cfg add port-group:Ports 0 2-17;4;9;22
 *  npf-cfg commit
 *
 * Handling these other uses of groups will require a slightly different entry
 * point for parsing, and annotation in the classes of configuration group.
 *
 * Of these, 'protocol' and 'dscp' are simply semi-colon split integers,
 * 'port' is a semi-colon split list of port ranges, 'icmp' and 'icmpv6'
 * are semi-colon split lists of their base type.
 *
 * These can be implemented later, since initially ACLs will not support any
 * resource groups.
 */

struct pkp_key;
typedef bool pkp_key_parser(struct pmf_rule *rule, struct pkp_key const *key,
				char *value);

enum pkp_mlayer {
	ML2 = 1,
	ML3,
	ML4,
};

struct pkp_key {
	char const	*pt_name;
	uint8_t		pt_field;
	enum pkp_mlayer	pt_layer : 8;
	pkp_key_parser *pt_fn;
};

/* The match parsers */
static pkp_key_parser pkp_eth_mac;
static pkp_key_parser pkp_eth_type;
static pkp_key_parser pkp_eth_pcp;
static pkp_key_parser pkp_family;

static pkp_key_parser pkp_ipaddr;
static pkp_key_parser pkp_addr_grp;
static pkp_key_parser pkp_proto;
static pkp_key_parser pkp_proto_grp;
static pkp_key_parser pkp_dscp;
static pkp_key_parser pkp_dscp_grp;
static pkp_key_parser pkp_ttl;
static pkp_key_parser pkp_fragment;
static pkp_key_parser pkp_v6route;

static pkp_key_parser pkp_l4port;
static pkp_key_parser pkp_port_grp;
static pkp_key_parser pkp_tcpflgs;
static pkp_key_parser pkp_icmp;
static pkp_key_parser pkp_icmp_class;
static pkp_key_parser pkp_icmp_grp;

/* The action parsers */
static pkp_key_parser pkp_fate;
static pkp_key_parser pkp_stateful;
static pkp_key_parser pkp_nat_type;
static pkp_key_parser pkp_nat_pinhole;
static pkp_key_parser pkp_nat_exclude;
static pkp_key_parser pkp_nat_masq;
static pkp_key_parser pkp_nat_port;
static pkp_key_parser pkp_nat_addr_grp;
static pkp_key_parser pkp_nat_arange;

/* The rproc parser */
static pkp_key_parser pkp_rproc;

/* Types of action and nat keys */
enum pkp_act_field {
	PKP_ACT_FATE  = 1,
	PKP_ACT_STATEFUL,
	PKP_ACT_NAT_TYPE,
	PKP_ACT_NAT_PINHOLE,
	PKP_ACT_NAT_EXCLUDE,
	PKP_ACT_NAT_MASQ,
	PKP_ACT_NAT_PORT,
	PKP_ACT_NAT_ADDR,
	PKP_ACT_NAT_ADDR_GROUP,
	PKP_ACT__LEN
};

/* Types of rprocs */
enum pkp_rp_field {
	PKP_RP_MATCH = 1,
	PKP_RP_ACTION,
	PKP_RP_HANDLE,
	PKP_RP__LEN
};

/*
 * Keys appear in the input string in the form "key=value", where valid values
 * depends upon the type of the key.  Value may not contain an equals sign.
 *
 * The set of keys are space separated, so space may not appear within a key
 * or a value.  Some values are multipart, and these are semicolon separated.
 *
 * Finally for rprocs, the value may be in the form "name(subval)" where subval
 * may have multiple comma separated values.  The value itself may also contain
 * multiple "name(subval)" portions, each semicolon separated.
 */
static const struct pkp_key match_keys[] = {
	/* L2 */
	{"src-mac",		PMF_L2F_ETH_SRC,	ML2, pkp_eth_mac},
	{"dst-mac",		PMF_L2F_ETH_DST,	ML2, pkp_eth_mac},
	{"ether-type",		PMF_L2F_ETH_TYPE,	ML2, pkp_eth_type},
	{"pcp",			PMF_L2F_ETH_PCP,	ML2, pkp_eth_pcp},
	{"family",		PMF_L2F_IP_FAMILY,	ML2, pkp_family},
	/* L3 */
	{"src-addr",		PMF_L3F_SRC,		ML3, pkp_ipaddr},
	{"src-addr-group",	PMF_L3F_SRC,		ML3, pkp_addr_grp},
	{"dst-addr",		PMF_L3F_DST,		ML3, pkp_ipaddr},
	{"dst-addr-group",	PMF_L3F_DST,		ML3, pkp_addr_grp},
	{"proto-final",		PMF_L3F_PROTOF,		ML3, pkp_proto},
	{"proto-base",		PMF_L3F_PROTOB,		ML3, pkp_proto},
	{"proto",		PMF_L3F_PROTO,		ML3, pkp_proto},
	{"protocol-group",	PMF_L3F_PROTO,		ML3, pkp_proto_grp},
	{"dscp",		PMF_L3F_DSCP,		ML3, pkp_dscp},
	{"dscp-group",		PMF_L3F_DSCP,		ML3, pkp_dscp_grp},
	{"ttl",			PMF_L3F_TTL,		ML3, pkp_ttl},
	{"fragment",		PMF_L3F_FRAG,		ML3, pkp_fragment},
	{"ipv6-route",		PMF_L3F_RH,		ML3, pkp_v6route},
	/* L4 */
	{"src-port",		PMF_L4F_SRC,		ML4, pkp_l4port},
	{"src-port-group",	PMF_L4F_SRC,		ML4, pkp_port_grp},
	{"dst-port",		PMF_L4F_DST,		ML4, pkp_l4port},
	{"dst-port-group",	PMF_L4F_DST,		ML4, pkp_port_grp},
	{"tcp-flags",		PMF_L4F_TCP_FLAGS,	ML4, pkp_tcpflgs},
	{"icmpv4",		PMF_L4F_ICMP_VALS,	ML4, pkp_icmp},
	{"icmpv4-group",	PMF_L4F_ICMP_VALS,	ML4, pkp_icmp_grp},
	{"icmpv6",		PMF_L4F_ICMP_VALS,	ML4, pkp_icmp},
	{"icmpv6-class",	PMF_L4F_ICMP_VALS,	ML4, pkp_icmp_class},
	{"icmpv6-group",	PMF_L4F_ICMP_VALS,	ML4, pkp_icmp_grp},
};
static struct pkp_key action_keys[] = {
	/* Actions */
	{"action",		PKP_ACT_FATE,		0, pkp_fate},
	{"stateful",		PKP_ACT_STATEFUL,	0, pkp_stateful},
	{"nat-type",		PKP_ACT_NAT_TYPE,	0, pkp_nat_type},
	{"nat-pinhole",		PKP_ACT_NAT_PINHOLE,	0, pkp_nat_pinhole},
	{"nat-exclude",		PKP_ACT_NAT_EXCLUDE,	0, pkp_nat_exclude},
	{"trans-addr-masquerade", PKP_ACT_NAT_MASQ,	0, pkp_nat_masq},
	{"trans-port",		PKP_ACT_NAT_PORT,	0, pkp_nat_port},
	{"trans-addr-group",	PKP_ACT_NAT_ADDR_GROUP,	0, pkp_nat_addr_grp},
	{"trans-addr",		PKP_ACT_NAT_ADDR,	0, pkp_nat_arange},
};
static const struct pkp_key rproc_keys[] = {
	{"match",		PKP_RP_MATCH,		0, pkp_rproc},
	{"rproc",		PKP_RP_ACTION,		0, pkp_rproc},
	{"handle",		PKP_RP_HANDLE,		0, pkp_rproc},
};

/* Summary bits for the rule */
static uint32_t l2_summary[PMF_L2F__LEN] = {
	[PMF_L2F_ETH_SRC] = PMF_RMS_ETH_SRC,
	[PMF_L2F_ETH_DST] = PMF_RMS_ETH_DST,
	[PMF_L2F_ETH_TYPE] = PMF_RMS_ETH_TYPE,
	[PMF_L2F_ETH_PCP] = PMF_RMS_ETH_PCP,
	[PMF_L2F_IP_FAMILY] = PMF_RMS_IP_FAMILY,
};
static uint32_t l3_summary[PMF_L3F__LEN] = {
	[PMF_L3F_SRC] = PMF_RMS_L3_SRC,
	[PMF_L3F_DST] = PMF_RMS_L3_DST,
	[PMF_L3F_PROTOF] = PMF_RMS_L3_PROTO_FINAL,
	[PMF_L3F_PROTOB] = PMF_RMS_L3_PROTO_BASE,
	[PMF_L3F_DSCP] = PMF_RMS_L3_DSCP,
	[PMF_L3F_TTL] = PMF_RMS_L3_TTL,
	[PMF_L3F_FRAG] = PMF_RMS_L3_FRAG,
	[PMF_L3F_RH] = PMF_RMS_L3_RH,
};
static uint32_t l4_summary[PMF_L4F__LEN] = {
	[PMF_L4F_SRC] = PMF_RMS_L4_SRC,
	[PMF_L4F_DST] = PMF_RMS_L4_DST,
	[PMF_L4F_TCP_FLAGS] = PMF_RMS_L4_TCPFL,
	[PMF_L4F_ICMP_VALS] = PMF_RMS_L4_ICMP_TYPE,
};

/* Auxiliary functions: */

/*
 * Create and return an initial 'struct pmf_unused' based upon a single
 * string of space separated fields, the caller is eventually expect to
 * free() the returned struct.
 * It has 'num_pairs' and 'num_unused' set to number of fields, each
 * 'pair' within has only its 'key' field set; that to a new (writeable)
 * string identical to the equivalent supplied field.
 */
static int
pkp_split_parts(char const *rule_line, struct pkp_unused **remaining,
		char delimiter)
{
	if (!rule_line || !remaining)
		return -EINVAL;

	unsigned int slen = 0;
	unsigned int nparts = 0;

	/* Find number of space separated parts */
	for (char const *p = rule_line; *p; ++p, ++slen) {
		if (*p == delimiter)
			continue;
		++nparts;
		while (p[1] && p[1] != delimiter) {
			++slen; ++p;
		}
	}

	/* Allocate the part storage */
	struct pkp_unused *parts =
		calloc(1, 1 + slen +
			sizeof(*parts) + nparts * sizeof(parts->pairs[0]));
	if (!parts) {
		RTE_LOG(ERR, FIREWALL,
			"Error: parsed rule parts alloc failed\n");
		return -ENOMEM;
	}

	/* Copy the data */
	char * const new_rule = (char *)&parts->pairs[nparts];
	parts->num_pairs = nparts;
	parts->num_unused = nparts;
	memcpy(new_rule, rule_line, slen + 1);

	/* Split in to parts; space bounded */
	nparts = 0;
	for (char *p = new_rule; *p; ++p) {
		if (*p == delimiter)
			continue;
		parts->pairs[nparts++].key = p;
		while (p[1] && p[1] != delimiter)
			++p;
		if (p[1]) {
			p[1] = '\0';
			++p;
		}
	}

	*remaining = parts;

	return 0;
}

/*
 * Split the array of parts in to their key/value pairs.
 *
 * Each part is passed in as a 'key=value' string pointed to by the
 * 'key' field in its pair struct. Both 'num_pairs' and 'num_unused'
 * should be initialised to the number of elements in the 'pairs' field.
 *
 * On exit the 'key' field now points to the key alone (the '=' being
 * replaced with a '\0'), and the 'value' field points to the value alone.
 *
 * We verify that both 'key' and 'value' are not zero length.
 */
static int
pkp_split_pairs(struct pkp_unused *parts)
{
	/* Split the parts in to key/value; equals bounded */
	for (unsigned int nparts = 0; nparts < parts->num_pairs; ++nparts) {
		char *p = parts->pairs[nparts].key;
		while (*p && *p != '=')
			++p;
		if (*p) {
			*p++ = '\0';
			parts->pairs[nparts].value = p;
		} else {
			parts->pairs[nparts].value = (char *)empty_str;
		}
	}

	/* Sanity check that we had a set of "key=value" entries */
	for (unsigned int nparts = 0; nparts < parts->num_pairs; ++nparts) {
		char const *key = parts->pairs[nparts].key;
		char const *value = parts->pairs[nparts].value;

		if (!key || !value || !*key || !*value) {
			RTE_LOG(ERR, FIREWALL,
				"Error: rule not in key=value form\n");
			return -ENOTDIR;
		}
	}

	return 0;
}

/* The parsers for match keys */

static bool
pkp_eth_mac(struct pmf_rule *rule, struct pkp_key const *key, char *value)
{
	struct pmf_attr_emac emac = { .pm_tag = PMAT_ETH_MAC };

	uint8_t *ab = &emac.pm_emac[0];
	int count = 0;

	if (sscanf(value, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx%n",
		   ab, ab + 1, ab + 2, ab + 3, ab + 4, ab + 5, &count) != 6 ||
	    count != 17 || value[17] != '\0') {
		RTE_LOG(ERR, FIREWALL,
			"NPF: bad value in rule: %s=%s\n", key->pt_name, value);
		return false;
	}

	struct pmf_attr_emac *vp = pmf_leaf_attr_copy(&emac);
	if (!vp) {
		RTE_LOG(ERR, FIREWALL,
			"Error: No memory for parsed ether mac\n");
		return false;
	}

	rule->pp_match.l2[key->pt_field].pm_emac = vp;

	return true;
}

static bool
pkp_eth_type(struct pmf_rule *rule, struct pkp_key const *key, char *value)
{
	struct pmf_attr_etype etype = { .pm_tag = PMAT_ETH_TYPE };

	char *endp = NULL;
	unsigned long ether = strtoul(value, &endp, 10);
	if (endp == value || *endp || ether > 0xffff) {
		RTE_LOG(ERR, FIREWALL,
			"NPF: bad value in rule: %s=%s\n", key->pt_name, value);
		return false;
	}
	etype.pm_etype = ether;

	struct pmf_attr_etype *vp = pmf_leaf_attr_copy(&etype);
	if (!vp) {
		RTE_LOG(ERR, FIREWALL,
			"Error: No memory for parsed ether-type\n");
		return false;
	}

	rule->pp_match.l2[PMF_L2F_ETH_TYPE].pm_etype = vp;

	return true;
}

static bool
pkp_eth_pcp(struct pmf_rule *rule, struct pkp_key const *key, char *value)
{
	struct pmf_attr_epcp epcp = { .pm_tag = PMAT_ETH_PCP };

	char *endp = NULL;
	unsigned long pcp = strtoul(value, &endp, 10);
	if (endp == value || *endp || pcp > 7) {
		RTE_LOG(ERR, FIREWALL,
			"NPF: bad value in rule: %s=%s\n", key->pt_name, value);
		return false;
	}
	epcp.pm_pcp = pcp;

	struct pmf_attr_epcp *vp = pmf_leaf_attr_copy(&epcp);
	if (!vp) {
		RTE_LOG(ERR, FIREWALL,
			"Error: No memory for parsed pcp\n");
		return false;
	}

	rule->pp_match.l2[PMF_L2F_ETH_PCP].pm_epcp = vp;

	return true;
}

static bool
pkp_family(struct pmf_rule *rule, struct pkp_key const *key, char *value)
{
	struct pmf_attr_ip_family family = { .pm_tag = PMAT_IP_FAMILY };

	if (strcmp(value, "inet6") == 0)
		family.pm_v6 = true;
	else if (strcmp(value, "inet") != 0) {
		RTE_LOG(ERR, FIREWALL,
			"NPF: bad value in rule: %s=%s\n", key->pt_name, value);
		return false;
	}

	struct pmf_attr_ip_family *vp = pmf_leaf_attr_copy(&family);
	if (!vp) {
		RTE_LOG(ERR, FIREWALL,
			"Error: No memory for parsed family\n");
		return false;
	}

	rule->pp_match.l2[PMF_L2F_IP_FAMILY].pm_ipfam = vp;

	return true;
}

static struct pmf_attr_v4_range *
pkp_ip4addr_range(struct pkp_key const *key, char *value)
{
	struct pmf_attr_v4_range arange = { .pm_tag = PMAT_IPV4_RANGE };

	/* Extract the last address */
	char *dash = strchr(value, '-');
	if (dash) {
		char *str_last = dash + 1;

		int ret = inet_pton(AF_INET, str_last, arange.pm_last);
		if (ret != 1) {
			RTE_LOG(ERR, FIREWALL,
				"NPF: bad value in rule: %s=%s\n",
				key->pt_name, value);
			return NULL;
		}

		*dash = '\0';
	}

	/* Extract the first address */
	int ret = inet_pton(AF_INET, value, arange.pm_first);
	if (ret != 1) {
		if (dash)
			*dash = '-';
		RTE_LOG(ERR, FIREWALL,
			"NPF: bad value in rule: %s=%s\n",
			key->pt_name, value);
		return NULL;
	}

	if (dash)
		*dash = '-';
	else
		memcpy(arange.pm_last, arange.pm_first, sizeof(arange.pm_last));

	/* Allocate the parsed address range */
	struct pmf_attr_v4_range *vp = pmf_leaf_attr_copy(&arange);
	if (!vp) {
		RTE_LOG(ERR, FIREWALL,
			"Error: No memory for parsed range\n");
		return NULL;
	}

	return vp;
}

static bool
pkp_ipaddr(struct pmf_rule *rule, struct pkp_key const *key, char *value)
{
	int mask_len = -1;

	char *colon = strchr(value, ':');

	/* Extract the prefix length */
	char *slash = strchr(value, '/');
	if (slash) {
		char *str_mask = slash + 1;

		const uint8_t maxmask = (colon) ? 128 : 32;

		char *endp = NULL;
		unsigned long masklen = strtoul(str_mask, &endp, 10);
		if (endp == str_mask || *endp || masklen > maxmask) {
			RTE_LOG(ERR, FIREWALL,
				"NPF: bad value in rule: %s=%s\n",
				key->pt_name, value);
			return false;
		}

		mask_len = masklen;
		*slash = '\0';
	}

	/* Find start of address */
	char *str_addr = value;
	bool negate = false;

	if (*value == '!') {
		negate = true;
		++str_addr;
	}

	/* Parse the address */
	uint8_t abytes[16];

	int ret = inet_pton((colon) ? AF_INET6 : AF_INET, str_addr, abytes);
	if (slash)
		*slash = '/';
	if (ret != 1) {
		RTE_LOG(ERR, FIREWALL,
			"NPF: bad value in rule: %s=%s\n",
			key->pt_name, value);
		return false;
	}

	/* Create the representation */
	void *prefix;
	if (colon) {
		mask_len = (mask_len < 0) ? 128 : mask_len;
		prefix = pmf_v6_prefix_create(negate, mask_len, abytes);
	} else {
		mask_len = (mask_len < 0) ? 32 : mask_len;
		prefix = pmf_v4_prefix_create(negate, mask_len, abytes);
	}

	if (!prefix) {
		RTE_LOG(ERR, FIREWALL,
			"Error: No memory for parsed address\n");
		return false;
	}

	if (colon)
		rule->pp_match.l3[key->pt_field].pm_l3v6 = prefix;
	else
		rule->pp_match.l3[key->pt_field].pm_l3v4 = prefix;

	return true;
}

static bool
pkp_addr_grp(struct pmf_rule *rule, struct pkp_key const *key, char *value)
{
	struct pmf_attr_group_ref *ref = pmf_create_addr_group_ref(value);
	if (!ref) {
		RTE_LOG(ERR, FIREWALL,
			"Error: No memory for parsed address group\n");
		return false;
	}

	rule->pp_match.l3[key->pt_field].pm_l3group = ref;

	return true;
}

static bool
pkp_proto(struct pmf_rule *rule, struct pkp_key const *key, char *value)
{
	struct pmf_attr_proto ip_proto = { .pm_tag = PMAT_IP_PROTO };

	ip_proto.pm_final = (key->pt_field == PMF_L3F_PROTOF);
	ip_proto.pm_base = (key->pt_field == PMF_L3F_PROTOB);

	/*
	 * The protocol field is only 8 bits, and so valid values
	 * are 0 through 255 inclusive.  We allow the value of 256
	 * to be used in combination with "proto-final" as a way
	 * of indicating that the final protocol is unknown.
	 *
	 * This can occur in IPv6 when extension chains
	 * (e.g. fragment, followed by destination options) mean
	 * that the final protocol can not be determined.  While
	 * this has now been disallowed in the RFCs, we still
	 * have to be able to match and discard such packets.
	 */
	char *endp = NULL;
	unsigned long proto = strtoul(value, &endp, 10);
	if (endp == value || *endp || proto > 256) {
error:
		RTE_LOG(ERR, FIREWALL,
			"NPF: bad value in rule: %s=%s\n", key->pt_name, value);
		return false;
	}

	if (proto < 256)
		ip_proto.pm_proto = proto;
	else if (ip_proto.pm_final)
		ip_proto.pm_unknown = true;
	else
		goto error;

	struct pmf_attr_proto *vp = pmf_leaf_attr_copy(&ip_proto);
	if (!vp) {
		RTE_LOG(ERR, FIREWALL,
			"Error: No memory for parsed proto\n");
		return false;
	}

	rule->pp_match.l3[key->pt_field].pm_l3proto = vp;

	return true;
}

static bool
pkp_proto_grp(struct pmf_rule *rule,
		struct pkp_key const *key __unused, char *value)
{
	struct pmf_attr_group_ref *ref = pmf_create_proto_group_ref(value);
	if (!ref) {
		RTE_LOG(ERR, FIREWALL,
			"Error: No memory for parsed proto group\n");
		return false;
	}

	rule->pp_match.l3[PMF_L3F_PROTO].pm_l3group = ref;

	return true;
}

static bool
pkp_dscp(struct pmf_rule *rule, struct pkp_key const *key, char *value)
{
	struct pmf_attr_dscp ip_dscp = { .pm_tag = PMAT_IP_DSCP };

	char *endp = NULL;
	unsigned long dscp = strtoul(value, &endp, 10);
	if (endp == value || *endp || dscp > 63) {
		RTE_LOG(ERR, FIREWALL,
			"NPF: bad value in rule: %s=%s\n", key->pt_name, value);
		return false;
	}
	ip_dscp.pm_dscp = dscp;

	struct pmf_attr_dscp *vp = pmf_leaf_attr_copy(&ip_dscp);
	if (!vp) {
		RTE_LOG(ERR, FIREWALL,
			"Error: No memory for parsed dscp\n");
		return false;
	}

	rule->pp_match.l3[PMF_L3F_DSCP].pm_l3dscp = vp;

	return true;
}

static bool
pkp_dscp_grp(struct pmf_rule *rule,
		struct pkp_key const *key __unused, char *value)
{
	struct pmf_attr_group_ref *ref = pmf_create_dscp_group_ref(value);
	if (!ref) {
		RTE_LOG(ERR, FIREWALL,
			"Error: No memory for parsed dscp group\n");
		return false;
	}

	rule->pp_match.l3[PMF_L3F_DSCP].pm_l3group = ref;

	return true;
}

static bool
pkp_ttl(struct pmf_rule *rule, struct pkp_key const *key, char *value)
{
	struct pmf_attr_ttl ip_ttl = { .pm_tag = PMAT_IP_TTL };

	char *endp = NULL;
	unsigned long ttl = strtoul(value, &endp, 10);
	if (endp == value || *endp || ttl > 255) {
		RTE_LOG(ERR, FIREWALL,
			"NPF: bad value in rule: %s=%s\n", key->pt_name, value);
		return false;
	}
	ip_ttl.pm_ttl = ttl;

	struct pmf_attr_ttl *vp = pmf_leaf_attr_copy(&ip_ttl);
	if (!vp) {
		RTE_LOG(ERR, FIREWALL,
			"Error: No memory for parsed ttl\n");
		return false;
	}

	rule->pp_match.l3[PMF_L3F_TTL].pm_l3ttl = vp;

	return true;
}

static bool
pkp_fragment(struct pmf_rule *rule, struct pkp_key const *key, char *value)
{
	struct pmf_attr_frag ip_frag = { .pm_tag = PMAT_IP_FRAG };
	bool frag = false;

	if (strcmp(value, "y") == 0)
		frag = true;
	else if (strcmp(value, "n") != 0) {
		RTE_LOG(ERR, FIREWALL,
			"NPF: bad value in rule: %s=%s\n", key->pt_name, value);
		return false;
	}

	if (!frag)
		return true;

	struct pmf_attr_frag *vp = pmf_leaf_attr_copy(&ip_frag);
	if (!vp) {
		RTE_LOG(ERR, FIREWALL,
			"Error: No memory for parsed fragment\n");
		return false;
	}

	rule->pp_match.l3[PMF_L3F_FRAG].pm_l3frag = vp;

	return true;
}

static bool
pkp_v6route(struct pmf_rule *rule, struct pkp_key const *key, char *value)
{
	struct pmf_attr_v6_rh v6_rh = { .pm_tag = PMAT_IPV6_RH };

	char *endp = NULL;
	unsigned long rtype = strtoul(value, &endp, 10);
	if (endp == value || *endp || rtype > 255) {
		RTE_LOG(ERR, FIREWALL,
			"NPF: bad value in rule: %s=%s\n", key->pt_name, value);
		return false;
	}
	v6_rh.pm_type = rtype;

	struct pmf_attr_v6_rh *vp = pmf_leaf_attr_copy(&v6_rh);
	if (!vp) {
		RTE_LOG(ERR, FIREWALL,
			"Error: No memory for parsed ipv6 route\n");
		return false;
	}

	rule->pp_match.l3[PMF_L3F_RH].pm_l3v6rh = vp;

	return true;
}

static struct pmf_attr_l4port_range *
pkp_l4port_core(struct pkp_key const *key, char *value)
{
	struct pmf_attr_l4port_range l4ports = { .pm_tag = PMAT_L4_PORT_RANGE };

	/* Extract the last port */
	char *dash = strchr(value, '-');
	if (dash) {
		char *str_last = dash + 1;

		char *endp = NULL;
		unsigned long lastport = strtoul(str_last, &endp, 10);
		if (endp == str_last || *endp || lastport > 0xffff) {
			RTE_LOG(ERR, FIREWALL,
				"NPF: bad value in rule: %s=%s\n",
				key->pt_name, value);
			return NULL;
		}

		l4ports.pm_hiport = lastport;
		*dash = '\0';
	}

	char *endp = NULL;
	unsigned long firstport = strtoul(value, &endp, 10);
	if (endp == value || *endp || firstport > 0xffff) {
		if (dash)
			*dash = '-';
		RTE_LOG(ERR, FIREWALL,
			"NPF: bad value in rule: %s=%s\n",
			key->pt_name, value);
		return NULL;
	}

	l4ports.pm_loport = firstport;
	if (dash)
		*dash = '-';
	else
		l4ports.pm_hiport = l4ports.pm_loport;

	struct pmf_attr_l4port_range *vp = pmf_leaf_attr_copy(&l4ports);
	if (!vp) {
		RTE_LOG(ERR, FIREWALL,
			"Error: No memory for parsed port range\n");
		return NULL;
	}

	return vp;
}

static bool
pkp_l4port(struct pmf_rule *rule, struct pkp_key const *key, char *value)
{
	struct pmf_attr_l4port_range *vp = pkp_l4port_core(key, value);

	if (!vp)
		return false;

	rule->pp_match.l4[key->pt_field].pm_l4port_range = vp;

	return true;
}

static bool
pkp_port_grp(struct pmf_rule *rule, struct pkp_key const *key, char *value)
{
	struct pmf_attr_group_ref *ref = pmf_create_port_group_ref(value);
	if (!ref) {
		RTE_LOG(ERR, FIREWALL,
			"Error: No memory for parsed port group\n");
		return false;
	}

	rule->pp_match.l4[key->pt_field].pm_l4group = ref;

	return true;
}

static bool
pkp_parse_tcpflag(char *oneflag, struct pmf_attr_l4tcp_flags *tcp_flags)
{
	bool negate = false;
	uint16_t flag = 0;	/* A 12 bit field */

	if (*oneflag == '!') {
		negate = true;
		++oneflag;
	}

	/* The flags; handle ECE & CWR manually */
	if (strcmp(oneflag, "SYN") == 0)
		flag = TH_SYN;
	else if (strcmp(oneflag, "ACK") == 0)
		flag = TH_ACK;
	else if (strcmp(oneflag, "FIN") == 0)
		flag = TH_FIN;
	else if (strcmp(oneflag, "RST") == 0)
		flag = TH_RST;
	else if (strcmp(oneflag, "PSH") == 0)
		flag = TH_PUSH;
	else if (strcmp(oneflag, "URG") == 0)
		flag = TH_URG;
	else if (strcmp(oneflag, "ECE") == 0)
		flag = 0x40;
	else if (strcmp(oneflag, "CWR") == 0)
		flag = 0x80;
	else
		return false;

	if (!negate)
		tcp_flags->pm_match |= flag;

	tcp_flags->pm_mask |= flag;

	return true;
}

static bool
pkp_tcpflgs(struct pmf_rule *rule, struct pkp_key const *key, char *value)
{
	struct pmf_attr_l4tcp_flags tcp_flgs = { .pm_tag = PMAT_L4_TCP_FLAGS };

	/* This parses: [!]<flag>[,[!]<flag>]* */
	char *oneflag;
	char *scan = value;

	while ((oneflag = strsep(&scan, ",")) != NULL) {
		bool good = pkp_parse_tcpflag(oneflag, &tcp_flgs);
		if (scan)
			scan[-1] = ','; /* revert to ',' from '\0' */
		if (!good) {
			RTE_LOG(ERR, FIREWALL,
				"NPF: unexpected value in rule: %s=%s\n",
				key->pt_name, value);
			return false;
		}
	}

	struct pmf_attr_l4tcp_flags *vp = pmf_leaf_attr_copy(&tcp_flgs);
	if (!vp) {
		RTE_LOG(ERR, FIREWALL,
			"Error: No memory for parsed tcp flags\n");
		return false;
	}

	rule->pp_match.l4[PMF_L4F_TCP_FLAGS].pm_l4tcp_flags = vp;

	return true;
}

static bool
pkp_icmp_num(char *value, bool is_v6, struct pmf_attr_l4icmp_vals *l4icmp)
{
	l4icmp->pm_named = false;

	/* Extract the code, if any */
	char *colon = strchr(value, ':');
	if (colon) {
		char *str_code = colon + 1;

		char *endp = NULL;
		unsigned long code_val = strtoul(str_code, &endp, 10);
		if (endp == str_code || *endp || code_val > 255) {
			RTE_LOG(ERR, FIREWALL,
				"NPF: bad value in rule: icmp%s=%s\n",
				(is_v6) ? "v6" : "v4", value);
			return false;
		}

		l4icmp->pm_code = code_val;
		l4icmp->pm_any_code = false;
		*colon = '\0';
	}

	char *endp = NULL;
	unsigned long type_val = strtoul(value, &endp, 10);
	if (endp == value || *endp || type_val > 255) {
		if (colon)
			*colon = ':';
		RTE_LOG(ERR, FIREWALL,
			"NPF: bad value in rule: icmp%s=%s\n",
			(is_v6) ? "v6" : "v4", value);
		return false;
	}

	l4icmp->pm_type = type_val;

	if (colon)
		*colon = ':';
	else
		l4icmp->pm_any_code = true;


	return true;
}

struct pkp_icmp_table {
	const char *name;
	int16_t type;
	int16_t code;
};

static struct pkp_icmp_table pkp_tab_icv4[] = {
	{ "echo-reply",					0,	-1 },
	{ "destination-unreachable",			3,	-1 },
	{ "network-unreachable",			3,	0 },
	{ "host-unreachable",				3,	1 },
	{ "protocol-unreachable",			3,	2 },
	{ "port-unreachable",				3,	3 },
	{ "fragmentation-needed",			3,	4 },
	{ "source-route-failed",			3,	5 },
	{ "network-unknown",				3,	6 },
	{ "host-unknown",				3,	7 },
	{ "network-prohibited",				3,	9 },
	{ "host-prohibited",				3,	10 },
	{ "TOS-network-unreachable",			3,	11 },
	{ "TOS-host-unreachable",			3,	12 },
	{ "communication-prohibited",			3,	13 },
	{ "host-precedence-violation",			3,	14 },
	{ "precedence-cutoff",				3,	15 },
	{ "source-quench",				4,	-1 },
	{ "redirect",					5,	-1 },
	{ "network-redirect",				5,	0 },
	{ "host-redirect",				5,	1 },
	{ "TOS-network-redirect",			5,	2 },
	{ "TOS-host-redirect",				5,	3 },
	{ "echo-request",				8,	-1 },
	{ "router-advertisement",			9,	-1 },
	{ "router-solicitation",			10,	-1 },
	{ "time-exceeded",				11,	-1 },
	{ "ttl-zero-during-transit",			11,	0 },
	{ "ttl-zero-during-reassembly",			11,	1 },
	{ "parameter-problem",				12,	-1 },
	{ "ip-header-bad",				12,	0 },
	{ "required-option-missing",			12,	1 },
	{ "timestamp-request",				13,	-1 },
	{ "timestamp-reply",				14,	-1 },
	{ "address-mask-request",			17,	-1 },
	{ "address-mask-reply",				18,	-1 },
};

static bool
pkp_icmp_v4(char *value, struct pmf_attr_l4icmp_vals *l4icmp)
{
	for (unsigned int idx = 0; idx < ARRAY_SIZE(pkp_tab_icv4); ++idx) {
		if (strcmp(value, pkp_tab_icv4[idx].name) != 0)
			continue;

		l4icmp->pm_type = pkp_tab_icv4[idx].type;
		if (pkp_tab_icv4[idx].code == -1)
			l4icmp->pm_any_code = true;
		else {
			l4icmp->pm_any_code = false;
			l4icmp->pm_code = pkp_tab_icv4[idx].code;
		}

		return true;
	}

	return false;
}

static struct pkp_icmp_table pkp_tab_icv6[] = {
	{ "destination-unreachable",			1,	-1 },
	{ "no-route",					1,	0 },
	{ "communication-prohibited",			1,	1 },
	{ "address-unreachable",			1,	3 },
	{ "port-unreachable",				1,	4 },
	{ "packet-too-big",				2,	-1 },
	{ "time-exceeded",				3,	-1 },
	{ "ttl-zero-during-transit",			3,	0 },
	{ "ttl-zero-during-reassembly",			3,	1 },
	{ "parameter-problem",				4,	-1 },
	{ "bad-header",					4,	0 },
	{ "unknown-header-type",			4,	1 },
	{ "unknown-option",				4,	2 },
	{ "echo-request",				128,	-1 },
	{ "echo-reply",					129,	-1 },
	{ "multicast-listener-query",			130,	-1 },
	{ "multicast-listener-report",			131,	-1 },
	{ "multicast-listener-done",			132,	-1 },
	{ "router-solicitation",			133,	-1 },
	{ "router-advertisement",			134,	-1 },
	{ "neighbor-solicitation",			135,	-1 },
	{ "neighbor-advertisement",			136,	-1 },
	{ "redirect",					137,	-1 },
	{ "mobile-prefix-solicitation",			146,	-1 },
	{ "mobile-prefix-advertisement",		147,	-1 },
};

static bool
pkp_icmp_v6(char *value, struct pmf_attr_l4icmp_vals *l4icmp)
{
	for (unsigned int idx = 0; idx < ARRAY_SIZE(pkp_tab_icv6); ++idx) {
		if (strcmp(value, pkp_tab_icv6[idx].name) != 0)
			continue;

		l4icmp->pm_type = pkp_tab_icv6[idx].type;
		if (pkp_tab_icv6[idx].code == -1)
			l4icmp->pm_any_code = true;
		else {
			l4icmp->pm_any_code = false;
			l4icmp->pm_code = pkp_tab_icv6[idx].code;
		}

		return true;
	}

	return false;
}

static bool
pkp_icmp(struct pmf_rule *rule, struct pkp_key const *key, char *value)
{
	struct pmf_attr_l4icmp_vals l4icmp = { 0 };

	bool is_v6 = (strcmp(key->pt_name, "icmpv6") == 0);
	l4icmp.pm_tag = (is_v6) ? PMAT_L4_ICMP_V6_VALS : PMAT_L4_ICMP_V4_VALS;
	l4icmp.pm_named = true;

	bool good;

	if (isdigit(*value))
		good = pkp_icmp_num(value, is_v6, &l4icmp);
	else if (is_v6)
		good = pkp_icmp_v6(value, &l4icmp);
	else
		good = pkp_icmp_v4(value, &l4icmp);

	if (!good) {
		RTE_LOG(ERR, FIREWALL,
			"NPF: unexpected value in rule: %s=%s\n",
			key->pt_name, value);
		return false;
	}

	struct pmf_attr_l4icmp_vals *vp = pmf_leaf_attr_copy(&l4icmp);
	if (!vp) {
		RTE_LOG(ERR, FIREWALL,
			"Error: No memory for parsed icmp%s values\n",
			(is_v6) ? "v6" : "v4");
		return false;
	}

	if (!vp->pm_any_code)
		rule->pp_summary |= PMF_RMS_L4_ICMP_CODE;
	rule->pp_match.l4[PMF_L4F_ICMP_VALS].pm_l4icmp_vals = vp;

	return true;
}

static bool
pkp_icmp_class(struct pmf_rule *rule, struct pkp_key const *key, char *value)
{
	struct pmf_attr_l4icmp_vals l4icmp = { 0 };

	bool is_v6 = (strcmp(key->pt_name, "icmpv6-class") == 0);
	l4icmp.pm_tag = (is_v6) ? PMAT_L4_ICMP_V6_VALS : PMAT_L4_ICMP_V4_VALS;
	l4icmp.pm_named = false;
	l4icmp.pm_any_code = true;
	l4icmp.pm_class = true;

	/*
	 * Only IPv6 supported for the moment, and 'info' class has a match
	 * and mask of 0x80 due to the way the ICMPv6 messages are designed.
	 */
	if (strcmp(value, "info") == 0)
		l4icmp.pm_type = ICMP6_INFOMSG_MASK;
	else if (strcmp(value, "error") != 0) {
		RTE_LOG(ERR, FIREWALL,
			"NPF: bad value in rule: %s=%s\n", key->pt_name, value);
		return false;
	}

	struct pmf_attr_l4icmp_vals *vp = pmf_leaf_attr_copy(&l4icmp);
	if (!vp) {
		RTE_LOG(ERR, FIREWALL,
			"Error: No memory for parsed icmp%s values\n",
			(is_v6) ? "v6" : "v4");
		return false;
	}

	rule->pp_match.l4[PMF_L4F_ICMP_VALS].pm_l4icmp_vals = vp;

	return true;
}

static bool
pkp_icmp_grp(struct pmf_rule *rule, struct pkp_key const *key, char *value)
{
	bool is_v6 = (strcmp(key->pt_name, "icmpv6-group") == 0);

	struct pmf_attr_group_ref *ref =
		pmf_create_icmp_group_ref(value, is_v6);
	if (!ref) {
		RTE_LOG(ERR, FIREWALL,
			"Error: No memory for parsed icmpv%c group\n",
			is_v6 ? '6' : '4');
		return false;
	}

	rule->pp_match.l4[PMF_L4F_ICMP_VALS].pm_l4group = ref;

	return true;
}

static struct pkp_key const *
pkp_find_match_key(const char *key)
{
	for (unsigned int idx = 0; idx < ARRAY_SIZE(match_keys); ++idx)
		if (strcmp(key, match_keys[idx].pt_name) == 0)
			return &match_keys[idx];

	return NULL;
}

/* The parsers for fate (action) keys */

static bool
pkp_fate(struct pmf_rule *rule, struct pkp_key const *key, char *value)
{
	enum pmf_value rule_fate = PMV_UNSET;

	if (strcmp(value, "accept") == 0) {
		rule_fate = PMV_TRUE;
		rule->pp_summary |= PMF_RAS_PASS;
	} else if (strcmp(value, "drop") == 0) {
		rule_fate = PMV_FALSE;
		rule->pp_summary |= PMF_RAS_DROP;
	} else {
		RTE_LOG(ERR, FIREWALL,
			"NPF: unexpected value in rule: %s=%s\n",
			key->pt_name, value);
		return false;
	}

	rule->pp_action.fate = rule_fate;

	return true;
}

static bool
pkp_stateful(struct pmf_rule *rule, struct pkp_key const *key, char *value)
{
	enum pmf_value rule_stateful = PMV_UNSET;

	if (strcmp(value, "y") == 0)
		rule_stateful = PMV_TRUE;
	else if (strcmp(value, "n") == 0)
		rule_stateful = PMV_FALSE;
	else {
		RTE_LOG(ERR, FIREWALL,
			"NPF: unexpected value in rule: %s=%s\n",
			key->pt_name, value);
		return false;
	}

	rule->pp_action.stateful = rule_stateful;

	return true;
}

static struct pmf_nat *
pkp_nat_attach(struct pmf_rule *rule)
{
	struct pmf_nat *nat = rule->pp_action.nat;

	if (nat)
		return nat;

	nat = pmf_nat_create();
	if (!nat) {
		RTE_LOG(ERR, FIREWALL,
			"Error: No memory for parsed nat type\n");
		return NULL;
	}

	rule->pp_action.nat = nat;

	return nat;
}

static bool
pkp_nat_type(struct pmf_rule *rule, struct pkp_key const *key, char *value)
{
	enum pmf_nat_type nat_type;

	if (strcmp(value, "dnat") == 0)
		nat_type = PMN_DNAT;
	else if (strcmp(value, "snat") == 0)
		nat_type = PMN_SNAT;
	else {
		RTE_LOG(ERR, FIREWALL,
			"NPF: unexpected value in rule: %s=%s\n",
			key->pt_name, value);
		return false;
	}

	struct pmf_nat *nat = pkp_nat_attach(rule);
	if (!nat)
		return false;

	nat->pan_type = nat_type;

	return true;
}

static bool
pkp_nat_pinhole(struct pmf_rule *rule, struct pkp_key const *key, char *value)
{
	enum pmf_value nat_pinhole;

	if (strcmp(value, "y") == 0)
		nat_pinhole = PMV_TRUE;
	else if (strcmp(value, "n") == 0)
		nat_pinhole = PMV_FALSE;
	else {
		RTE_LOG(ERR, FIREWALL,
			"NPF: unexpected value in rule: %s=%s\n",
			key->pt_name, value);
		return false;
	}

	struct pmf_nat *nat = pkp_nat_attach(rule);
	if (!nat)
		return false;

	nat->pan_pinhole = nat_pinhole;

	return true;
}

static bool
pkp_nat_exclude(struct pmf_rule *rule, struct pkp_key const *key, char *value)
{
	enum pmf_value nat_exclude;

	if (strcmp(value, "y") == 0)
		nat_exclude = PMV_TRUE;
	else if (strcmp(value, "n") == 0)
		nat_exclude = PMV_FALSE;
	else {
		RTE_LOG(ERR, FIREWALL,
			"NPF: unexpected value in rule: %s=%s\n",
			key->pt_name, value);
		return false;
	}

	struct pmf_nat *nat = pkp_nat_attach(rule);
	if (!nat)
		return false;

	nat->pan_exclude = nat_exclude;

	return true;
}

static bool
pkp_nat_masq(struct pmf_rule *rule, struct pkp_key const *key, char *value)
{
	enum pmf_value nat_masq;

	if (strcmp(value, "y") == 0)
		nat_masq = PMV_TRUE;
	else if (strcmp(value, "n") == 0)
		nat_masq = PMV_FALSE;
	else {
		RTE_LOG(ERR, FIREWALL,
			"NPF: unexpected value in rule: %s=%s\n",
			key->pt_name, value);
		return false;
	}

	struct pmf_nat *nat = pkp_nat_attach(rule);
	if (!nat)
		return false;

	nat->pan_masquerade = nat_masq;

	return true;
}

static bool
pkp_nat_port(struct pmf_rule *rule, struct pkp_key const *key, char *value)
{
	struct pmf_attr_l4port_range *vp = pkp_l4port_core(key, value);

	if (!vp)
		return false;

	struct pmf_nat *nat = pkp_nat_attach(rule);
	if (!nat) {
		free(vp);
		return false;
	}

	nat->pan_tports = vp;

	return true;
}

static bool
pkp_nat_addr_grp(struct pmf_rule *rule,
		struct pkp_key const *key __unused, char *value)
{
	struct pmf_attr_group_ref *ref = pmf_create_addr_group_ref(value);
	if (!ref) {
		RTE_LOG(ERR, FIREWALL,
			"Error: No memory for parsed address group\n");
		return false;
	}

	struct pmf_nat *nat = pkp_nat_attach(rule);
	if (!nat) {
		free(ref);
		return false;
	}

	if (nat->pan_taddr.any) {
		RTE_LOG(ERR, FIREWALL,
			"Error: Can not use address group and address range\n");
		free(ref);
		return false;
	}

	nat->pan_taddr.group = ref;

	return true;
}

static bool
pkp_nat_arange(struct pmf_rule *rule, struct pkp_key const *key, char *value)
{
	struct pmf_attr_v4_range *vp = pkp_ip4addr_range(key, value);

	if (!vp)
		return false;

	struct pmf_nat *nat = pkp_nat_attach(rule);
	if (!nat) {
		free(vp);
		return false;
	}

	if (nat->pan_taddr.any) {
		RTE_LOG(ERR, FIREWALL,
			"Error: Can not use address group and address range\n");
		free(vp);
		return false;
	}

	nat->pan_taddr.range = vp;

	return true;
}

static struct pkp_key const *
pkp_find_action_key(const char *key)
{
	for (unsigned int idx = 0; idx < ARRAY_SIZE(action_keys); ++idx)
		if (strcmp(key, action_keys[idx].pt_name) == 0)
			return &action_keys[idx];

	return NULL;
}

/* The parsers for rproc (match/action/handle) keys */

static bool
pkp_rproc(struct pmf_rule *rule, struct pkp_key const *key, char *value)
{
	unsigned int nprocs = 0;
	uint32_t summary = 0;

	/* Find number of semi-colon separated parts */
	for (char *p = value; *p; ++p) {
		if (*p == ';')
			continue;
		++nprocs;
		while (p[1] && p[1] != ';')
			++p;
	}

	if (nprocs > 253) {
		RTE_LOG(ERR, FIREWALL,
			"Error: too many rule rprocs(%s)\n",
			key->pt_name);
		return false;
	}

	/* Allocate the rproc extension storage */
	struct pmf_pext_list *rpexts = NULL;
	enum npf_rproc_type rp_type;
	switch (key->pt_field) {
	case PKP_RP_MATCH:
		rpexts = pmf_rproc_mlist_create(nprocs);
		rp_type = NPF_RPROC_TYPE_MATCH;
		break;
	case PKP_RP_ACTION:
		rpexts = pmf_rproc_alist_create(nprocs);
		rp_type = NPF_RPROC_TYPE_ACTION;
		break;
	case PKP_RP_HANDLE:
		rpexts = pmf_rproc_hlist_create(nprocs);
		rp_type = NPF_RPROC_TYPE_HANDLE;
		break;
	default:
		RTE_LOG(ERR, FIREWALL,
			"Error: Unhandled rproc(%s) type\n",
			key->pt_name);
		return false;
	}

	if (!rpexts) {
		RTE_LOG(ERR, FIREWALL,
			"Error: split rule rproc(%s) alloc failed\n",
			key->pt_name);
		return false;
	}

	/* Split the string in to parts, semi-colon bounded. */
	nprocs = 0;
	char *cursor;
	for (cursor = value; *cursor; ++cursor) {
		if (*cursor == ';')
			continue;
		rpexts->pm_procs[nprocs++].pp_str = cursor;
		while (cursor[1] && cursor[1] != ';')
			++cursor;
		if (cursor[1]) {
			cursor[1] = '\0';
			++cursor;
		}
	}

	/* Pass over list again, this time creating raw rproc structs */
	for (unsigned int itm = nprocs; itm > 0; --itm) {
		unsigned int idx = itm - 1;
		char *str = rpexts->pm_procs[idx].pp_str;
		unsigned int str_len = 1 + (cursor - str);

		struct pmf_proc_raw *praw = pmf_rproc_raw_create(str_len, str);
		if (!praw) {
			while (++idx < nprocs)
				free(rpexts->pm_procs[idx].pp_raw);
			free(rpexts); /* NB - not pmf_rule_extension_free() */
			RTE_LOG(ERR, FIREWALL,
				"Error: raw rule rproc(%s) alloc failed\n",
				key->pt_name);
			return false;
		}

		rpexts->pm_procs[idx].pp_raw = praw;
	}

	/* It is now safe to use pmf_rule_extension_free() */

	/* Split in to name + args pairs */
	for (unsigned int idx = 0; idx < nprocs; ++idx) {
		union pmf_proc *proc = &rpexts->pm_procs[idx];
		struct pmf_proc_raw *praw = proc->pp_raw;

		char *str = praw->pm_name;

		char *lparen = strchr(str, '(');
		if (!lparen)
			continue;
		char *rparen = strchr(lparen+1, ')');
		if (!rparen || rparen[1] != '\0') {
			pmf_rule_extension_free(&rpexts);
			RTE_LOG(ERR, FIREWALL,
				"Error: bad rule rproc: %s=%s\n",
				key->pt_name, str);
			return false;
		}
		*lparen = '\0';
		praw->pm_argoff = (lparen+1) - str;
		*rparen = '\0';
	}

	/* Ensure that the rproc is actually known */
	for (unsigned int idx = 0; idx < nprocs; ++idx) {
		union pmf_proc *proc = &rpexts->pm_procs[idx];
		struct pmf_proc_raw *praw = proc->pp_raw;

		const npf_rproc_ops_t *rp_ops
			= npf_find_rproc(praw->pm_name, rp_type);

		if (!rp_ops) {
			pmf_rule_extension_free(&rpexts);
			RTE_LOG(ERR, FIREWALL,
				"Error: unknown rule rproc: %s\n",
				praw->pm_name);
			return false;
		}
		enum npf_rproc_id rp_id
			= npf_rproc_get_id(rp_ops);
		if (rp_id != NPF_RPROC_ID_LAST)
			praw->pm_id = rp_id;
		switch (rp_id) {
		case NPF_RPROC_ID_CTR_DEF:
			summary |= PMF_RAS_COUNT_DEF;
			break;
		case NPF_RPROC_ID_CTR_REF:
			summary |= PMF_RAS_COUNT_REF;
			break;
		default:
			break;
		}
		--rpexts->pm_unknown;
	}

	rule->pp_summary |= summary;

	switch (key->pt_field) {
	case PKP_RP_MATCH:
		rule->pp_match.extend = rpexts;
		break;
	case PKP_RP_ACTION:
		rule->pp_action.extend = rpexts;
		break;
	case PKP_RP_HANDLE:
		rule->pp_action.handle = rpexts;
		break;
	}

	return true;
}

static struct pkp_key const *
pkp_find_rproc_key(const char *key)
{
	for (unsigned int idx = 0; idx < ARRAY_SIZE(rproc_keys); ++idx)
		if (strcmp(key, rproc_keys[idx].pt_name) == 0)
			return &rproc_keys[idx];

	return NULL;
}

/*
 * Fill in an empty re-allocated 'struct pmf_rule' based upon a
 * passed in set of split key=value pairs, which we will try to
 * parse.
 *
 * We verify that the basic keys are only allowed to occur once,
 * and decrement the count of unused elements as they are consumed.
 */
static int
pkp_parse_rproc_pairs(struct pkp_unused *parts, struct pmf_rule *rule)
{
	/* Ensure no duplicate match fields */
	char rprocs[PKP_RP__LEN] = { 0 };

	/* Handle the parts we recognise */
	for (unsigned int part = 0; part < parts->num_pairs; ++part) {
		char const *str_key = parts->pairs[part].key;
		char *str_value = parts->pairs[part].value;

		/* A prior parser may have consumed some */
		if (!str_key)
			continue;

		/* Do we know this key? */
		struct pkp_key const *rkey = pkp_find_rproc_key(str_key);
		if (!rkey)
			continue;

		/* Avoid duplicate rprocs keys */
		if (rprocs[rkey->pt_field])
			return -EEXIST;
		++rprocs[rkey->pt_field];

		/* Parse the key/value */
		if (!rkey->pt_fn(rule, rkey, str_value))
			return -EINVAL;

		parts->pairs[part].key = NULL;
		--parts->num_unused;
	}

	return 0;
}

/*
 * Fill in an empty re-allocated 'struct pmf_rule' based upon a
 * passed in set of split key=value pairs, which we will try to
 * parse.
 *
 * We verify that the basic keys are only allowed to occur once,
 * and decrement the count of unused elements as they are consumed.
 */
static int
pkp_parse_rule_pairs(struct pkp_unused *parts, struct pmf_rule *rule)
{
	/* Ensure no duplicate match fields */
	char l2_matches[PMF_L2F__LEN] = { 0 };
	char l3_matches[PMF_L3F__LEN] = { 0 };
	char l4_matches[PMF_L4F__LEN] = { 0 };
	char actions[PKP_ACT__LEN] = { 0 };
	uint32_t summary = 0;

	/* First pass to handle any rprocs */
	int rc = pkp_parse_rproc_pairs(parts, rule);
	if (rc)
		return rc;

	/* Handle the parts we recognise */
	for (unsigned int part = 0; part < parts->num_pairs; ++part) {
		char const *str_key = parts->pairs[part].key;
		char *str_value = parts->pairs[part].value;

		/* A prior parser may have consumed some */
		if (!str_key)
			continue;

		/* Try for a match key first */
		struct pkp_key const *mkey = pkp_find_match_key(str_key);
		if (mkey) {
			/* Avoid duplicate match fields */
			switch (mkey->pt_layer) {
			case ML2:
				if (l2_matches[mkey->pt_field])
					return -EEXIST;
				summary |= l2_summary[mkey->pt_field];
				++l2_matches[mkey->pt_field];
				break;
			case ML3:
				if (l3_matches[mkey->pt_field])
					return -EEXIST;
				summary |= l3_summary[mkey->pt_field];
				++l3_matches[mkey->pt_field];
				break;
			case ML4:
				if (l4_matches[mkey->pt_field])
					return -EEXIST;
				summary |= l4_summary[mkey->pt_field];
				++l4_matches[mkey->pt_field];
				break;
			}

			/* Parse the key/value */
			if (!mkey->pt_fn(rule, mkey, str_value))
				return -EINVAL;

			parts->pairs[part].key = NULL;
			--parts->num_unused;
			continue;
		}

		/* Now try for an action key */
		struct pkp_key const *akey = pkp_find_action_key(str_key);
		if (akey) {
			/* Avoid duplicate action fields */
			if (actions[akey->pt_field])
				return -EEXIST;
			++actions[akey->pt_field];

			/* Parse the key/value */
			if (!akey->pt_fn(rule, akey, str_value))
				return -EINVAL;

			parts->pairs[part].key = NULL;
			--parts->num_unused;
		}
	}

	rule->pp_summary |= summary;

	/* Validate some NAT requirements */
	if (rule->pp_action.nat) {
		struct pmf_nat *nat = rule->pp_action.nat;
		if (nat->pan_type == PMN_UNSET) {
			RTE_LOG(ERR, FIREWALL,
				"NPF: Error - NAT rules require nat-type");
			return -EINVAL;
		}
	}

	return 0;
}

static int
pkp_parse_core_line(char const *rule_line, struct pmf_rule **prule,
			struct pkp_unused **remaining, bool full_rule)
{
	if (!rule_line || !prule || !remaining)
		return -EINVAL;

	struct pmf_rule *rule = pmf_rule_alloc();
	if (!rule) {
		RTE_LOG(ERR, FIREWALL,
			"Error: parsed rule alloc failed\n");
		return -ENOMEM;
	}

	/* Split the line in to a set of key/value fields */
	struct pkp_unused *parts = NULL;

	int rval = pkp_split_parts(rule_line, &parts, ' ');
	if (rval) {
exit_error:
		pmf_rule_free(rule);
		if (parts)
			free(parts);
		return rval;
	}

	/* Split the parts in to their pairs */
	rval = pkp_split_pairs(parts);
	if (rval)
		goto exit_error;

	/* Now parse the pairs */
	if (full_rule)
		rval = pkp_parse_rule_pairs(parts, rule);
	else
		rval = pkp_parse_rproc_pairs(parts, rule);
	if (rval)
		goto exit_error;

	*prule = rule;
	*remaining = parts;

	return 0;
}

/*
 * Parse rprocs out of a single string; Used for action-groups.
 */
int
pkp_parse_rproc_line(char const *rule_line, struct pmf_rule **prule,
			struct pkp_unused **remaining)
{
	return pkp_parse_core_line(rule_line, prule, remaining, false);
}

/*
 * Parse rule out of a single string.
 */
int
pkp_parse_rule_line(char const *rule_line, struct pmf_rule **prule,
			struct pkp_unused **remaining)
{
	return pkp_parse_core_line(rule_line, prule, remaining, true);
}

/*
 * Create and return an initial 'struct pmf_unused' based upon an array
 * of argv style strings, the caller is eventually expect to free() the
 * returned struct.
 * It has 'num_pairs' and 'num_unused' set to parameter 'nparts', each
 * 'pair' within has only its 'key' field set; that to a new (writeable)
 * string identical to the equivalent supplied argv[] element.
 */
static int
pkp_collect_parts(unsigned int nparts, char **av, struct pkp_unused **remaining)
{
	if (!nparts || !av || !remaining)
		return -EINVAL;

	unsigned int slen = 0;

	/* Find required part string storage */
	for (unsigned int idx = 0; idx < nparts; ++idx)
		slen += 1 + strlen(av[idx]);

	/* Allocate the part storage */
	struct pkp_unused *parts =
		calloc(1, 1 + slen +
			sizeof(*parts) + nparts * sizeof(parts->pairs[0]));
	if (!parts) {
		RTE_LOG(ERR, FIREWALL,
			"Error: parsed rule parts alloc failed\n");
		return -ENOMEM;
	}

	char *p = (char *)&parts->pairs[nparts];
	parts->num_pairs = nparts;
	parts->num_unused = nparts;

	/* Collect the parts */
	for (unsigned int idx = 0; idx < nparts; ++idx) {
		unsigned int plen = 1 + strlen(av[idx]);
		memcpy(p, av[idx], plen);

		parts->pairs[idx].key = p;
		p += plen;
	}

	*remaining = parts;

	return 0;
}

/*
 * Parse rule out of an argv style array of strings.
 *
 * In the returned 'struct rmf_unused', for recognised keys in a pair, the 'key'
 * field is NULLed, and the 'num_unused' element indicates if any of the keys in
 * a 'pair' were no recognised, in which its key and value fields are still
 * present.
 *
 * Hence the caller can attempt to further parse such elements.  It is intended
 * that this could be used for parsing rprocs.
 */
int
pkp_parse_args(unsigned int ac, char **av, struct pmf_rule **prule,
		struct pkp_unused **remaining)
{
	if (!ac || !av || !prule || !remaining)
		return -EINVAL;

	struct pmf_rule *rule = pmf_rule_alloc();
	if (!rule) {
		RTE_LOG(ERR, FIREWALL,
			"Error: parsed rule alloc failed\n");
		return -ENOMEM;
	}

	/* Copy and collect the arguments in to a parts array */
	struct pkp_unused *parts = NULL;

	int rval = pkp_collect_parts(ac, av, &parts);
	if (rval) {
exit_error:
		pmf_rule_free(rule);
		if (parts)
			free(parts);
		return rval;
	}

	/* Split the parts in to their pairs */
	rval = pkp_split_pairs(parts);
	if (rval)
		goto exit_error;

	/* Now parse the pairs */
	rval = pkp_parse_rule_pairs(parts, rule);
	if (rval)
		goto exit_error;

	*prule = rule;
	*remaining = parts;

	return 0;
}
