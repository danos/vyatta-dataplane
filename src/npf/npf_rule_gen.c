/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * This looks at all the configuration that can be applied to a rule
 * and generates the ncode for the rule and the grouper matches
 * and masks.
 *
 * The configuration is sent for each rule line in the format:
 *
 *	<var>=<value> <var>=<value> ...
 *
 * The currently supported variables and the format of values they can take are:
 *
 *	action=accept|drop
 *
 *	proto=<protocol-no>
 *	proto-final=<protocol-no>
 *	proto-base=<protocol-no>
 *	protocol-group=<resource-group>
 *
 *	src-addr=[!]<IPv4 or IPv6 address>[/<mask-len>]
 *	src-addr-group=<resource-group>
 *	src-mac=<mac-address>
 *	src-port=<start-no>[-<end-no>]
 *	src-port-group=<resource-group>
 *	dst-addr=[!]<IPv4 or IPv6 address>[/<mask-len>]
 *	dst-addr-group=<resource-group>
 *	dst-mac=<mac-address>
 *	dst-port=<start-no>[-<end-no>]
 *	dst-port-group=<resource-group>
 *
 *	icmpv4=<type>[:<code>]|<symbolic-icmpv4-type-name>
 *	icmpv4-group=<resource-group>
 *	icmpv6=<type>[:<code>]|<symbolic-icmpv6-type-name>
 *	icmpv6-group=<resource-group>
 *
 *	tcp-flags=[!]<flag>[,[!]<flag>]*
 *	ipv6-route=<value>
 *	dscp=<value>
 *	dscp-group=<resource-group>
 *	pcp=<value>
 *	ether-type=<type-no>
 *	stateful=y
 *	fragment=y
 *	tag=<value>
 *
 *	rproc=<name>[(<param>[,<param>])][;<name>[(<param>[,<param>])]]
 *
 *	family=inet|inet6
 *
 *	nat-type=dnat|snat
 *	nat-exclude=y
 *	nat-pinhole=y
 *	trans-addr=<IPv4 address>[-<IPv4-address>]
 *	trans-addr-masquerade=y
 *	trans-addr-group=<resource-group>
 *	trans-port=<start-no>[-<end-no>]
 *
 * For a port resource group, the format of an entry is:
 *
 *	<start-no>-<end-no>[;<start-no>-<end-no>]*
 *
 * For an ICMP resource group, the format of an entry is:
 *
 *	<type>[:<code>]|<symbolic-icmpv4/v6-type-name>
 *		[;<type>[:<code>]|<symbolic-icmpv4/v6-type-name>]*
 *
 * For DSCP and protocol resource groups, the format of an entry is:
 *
 *	<value>[;<value>]*
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <rte_ether.h>
#include <rte_log.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <urcu/list.h>

#include "if_var.h"
#include "npf/config/npf_attach_point.h"
#include "npf/config/npf_rule_group.h"
#include "npf/npf_addrgrp.h"
#include "npf/npf_nat.h"
#include "npf/npf_ncgen.h"
#include "npf/npf_ncode.h"
#include "npf/npf_rule_gen.h"
#include "npf/npf_ruleset.h"
#include "npf/npf_cache.h"
#include "npf_tblset.h"
#include "vplane_log.h"

#define NPF_MATCH_ALL_MASK8	0xFF
#define NPF_MATCH_ALL_MASK16	0xFFFF

/*
 * Flags use to note which parts of the grouper has been filled in.
 */
enum npf_grouper_flags {
	GPR_SET_PROTO =			1 << 0,
	GPR_SET_IP_SRC_ADDR =		1 << 1,
	GPR_SET_IP_DST_ADDR =		1 << 2,
	GPR_SET_SRC_PORT =		1 << 3,
	GPR_SET_DST_PORT =		1 << 4,
	GPR_SET_ICMPV4_TYPE_CODE =	1 << 5,
	GPR_SET_ICMPV6_TYPE_CODE =	1 << 6,
};

/*
 * Holds context for the ncode and grouper when building them from
 * the rule configuration.
 */
struct npf_rule_ctx {
	nc_ctx_t *nc_ctx;
	uint32_t grouper_flags;
	struct npf_rule_grouper_info *grouper_info;
};

void buf_app_printf(char *buf, size_t *used_buf_len,
			   const size_t total_buf_len, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vsnprintf(buf + *used_buf_len, total_buf_len - *used_buf_len, format,
		  args);
	va_end(args);
	*used_buf_len += strlen(buf + *used_buf_len);
}

static int
npf_initialise_ctx(struct npf_rule_ctx *ctx)
{
	ctx->nc_ctx = npf_ncgen_create();
	if (!ctx->nc_ctx)
		return -ENOMEM;

	ctx->grouper_info->g_family = AF_UNSPEC;

	ctx->grouper_flags = 0;

	/*
	 * Set grouper to match all - these will be changed if
	 * grouper-supported match fields are configured.
	 */
	memset(ctx->grouper_info->g_v4_match, 0,
	       sizeof(ctx->grouper_info->g_v4_match));
	memset(ctx->grouper_info->g_v4_mask, 0xFF,
	       sizeof(ctx->grouper_info->g_v4_mask));

	memset(ctx->grouper_info->g_v6_match, 0,
	       sizeof(ctx->grouper_info->g_v6_match));
	memset(ctx->grouper_info->g_v6_mask, 0xFF,
	       sizeof(ctx->grouper_info->g_v6_mask));

	return 0;
}

/*
 * If a grouper entry is set more than once for a given position, then
 * there are multiple entries, and so that entry cannot be used, and
 * needs to be made to match all entries.
 */

static void
npf_grouper_add_proto(struct npf_rule_ctx *ctx, uint8_t match, uint8_t mask)
{
	if (ctx->grouper_flags & GPR_SET_PROTO) {
		match = 0;
		mask = NPF_MATCH_ALL_MASK8;
	}
	ctx->grouper_flags |= GPR_SET_PROTO;

	ctx->grouper_info->g_v4_match[NPC_GPR_PROTO_OFF_v4] = match;
	ctx->grouper_info->g_v4_mask[NPC_GPR_PROTO_OFF_v4] = mask;

	ctx->grouper_info->g_v6_match[NPC_GPR_PROTO_OFF_v6] = match;
	ctx->grouper_info->g_v6_mask[NPC_GPR_PROTO_OFF_v6] = mask;
}

static void
npf_grouper_add_ipv4_src(struct npf_rule_ctx *ctx, const uint8_t *match,
			 const uint8_t *mask)
{
	unsigned int i;

	for (i = 0; i < NPC_GPR_SADDR_LEN_v4; i++) {
		ctx->grouper_info->g_v4_match[NPC_GPR_SADDR_OFF_v4 + i] =
			match ? match[i] : 0;
		ctx->grouper_info->g_v4_mask[NPC_GPR_SADDR_OFF_v4 + i] =
			mask ? mask[i] : NPF_MATCH_ALL_MASK8;
	}
}

static void
npf_grouper_add_ipv4_dst(struct npf_rule_ctx *ctx, const uint8_t *match,
			 const uint8_t *mask)
{
	unsigned int i;

	for (i = 0; i < NPC_GPR_DADDR_LEN_v4; i++) {
		ctx->grouper_info->g_v4_match[NPC_GPR_DADDR_OFF_v4 + i] =
			match ? match[i] : 0;
		ctx->grouper_info->g_v4_mask[NPC_GPR_DADDR_OFF_v4 + i] =
			mask ? mask[i] : NPF_MATCH_ALL_MASK8;
	}
}

static void
npf_grouper_add_ipv6_src(struct npf_rule_ctx *ctx, const uint8_t *match,
			 const uint8_t *mask)
{
	unsigned int i;

	for (i = 0; i < NPC_GPR_SADDR_LEN_v6; i++) {
		ctx->grouper_info->g_v6_match[NPC_GPR_SADDR_OFF_v6 + i] =
			match ? match[i] : 0;
		ctx->grouper_info->g_v6_mask[NPC_GPR_SADDR_OFF_v6 + i] =
			mask ? mask[i] : NPF_MATCH_ALL_MASK8;
	}
}

static void
npf_grouper_add_ipv6_dst(struct npf_rule_ctx *ctx, const uint8_t *match,
			 const uint8_t *mask)
{
	unsigned int i;

	for (i = 0; i < NPC_GPR_DADDR_LEN_v6; i++) {
		ctx->grouper_info->g_v6_match[NPC_GPR_DADDR_OFF_v6 + i] =
			match ? match[i] : 0;
		ctx->grouper_info->g_v6_mask[NPC_GPR_DADDR_OFF_v6 + i] =
			mask ? mask[i] : NPF_MATCH_ALL_MASK8;
	}
}

static void
npf_grouper_add_ip_src(struct npf_rule_ctx *ctx, const uint8_t *match,
		       const uint8_t *mask)
{
	if (ctx->grouper_flags & GPR_SET_IP_SRC_ADDR) {
		match = NULL;
		mask = NULL;
	}
	ctx->grouper_flags |= GPR_SET_IP_SRC_ADDR;

	if (ctx->grouper_info->g_family == AF_INET)
		npf_grouper_add_ipv4_src(ctx, match, mask);
	else
		npf_grouper_add_ipv4_src(ctx, NULL, NULL);

	if (ctx->grouper_info->g_family == AF_INET6)
		npf_grouper_add_ipv6_src(ctx, match, mask);
	else
		npf_grouper_add_ipv6_src(ctx, NULL, NULL);
}

static void
npf_grouper_add_ip_dst(struct npf_rule_ctx *ctx, const uint8_t *match,
		       const uint8_t *mask)
{
	if (ctx->grouper_flags & GPR_SET_IP_DST_ADDR) {
		match = NULL;
		mask = NULL;
	}
	ctx->grouper_flags |= GPR_SET_IP_DST_ADDR;

	if (ctx->grouper_info->g_family == AF_INET)
		npf_grouper_add_ipv4_dst(ctx, match, mask);
	else
		npf_grouper_add_ipv4_dst(ctx, NULL, NULL);

	if (ctx->grouper_info->g_family == AF_INET6)
		npf_grouper_add_ipv6_dst(ctx, match, mask);
	else
		npf_grouper_add_ipv6_dst(ctx, NULL, NULL);
}

static void
npf_grouper_add_ip_addr(struct npf_rule_ctx *ctx, int options,
			const uint8_t *match, const uint8_t *mask)
{
	if (options & NC_MATCH_SRC)
		npf_grouper_add_ip_src(ctx, match, mask);
	else
		npf_grouper_add_ip_dst(ctx, match, mask);
}

static void
npf_grouper_add_src_port(struct npf_rule_ctx *ctx, uint16_t match,
			 uint16_t mask)
{
	if (ctx->grouper_flags & GPR_SET_SRC_PORT) {
		match = 0;
		mask = 0xFFFF;
	}
	ctx->grouper_flags |= GPR_SET_SRC_PORT;

	ctx->grouper_info->g_v4_match[NPC_GPR_SPORT_OFF_v4] = match >> 8;
	ctx->grouper_info->g_v4_match[NPC_GPR_SPORT_OFF_v4 + 1] = match & 0xFF;
	ctx->grouper_info->g_v4_mask[NPC_GPR_SPORT_OFF_v4] = mask >> 8;
	ctx->grouper_info->g_v4_mask[NPC_GPR_SPORT_OFF_v4 + 1] = mask & 0xFF;

	ctx->grouper_info->g_v6_match[NPC_GPR_SPORT_OFF_v6] = match >> 8;
	ctx->grouper_info->g_v6_match[NPC_GPR_SPORT_OFF_v6 + 1] = match & 0xFF;
	ctx->grouper_info->g_v6_mask[NPC_GPR_SPORT_OFF_v6] = mask >> 8;
	ctx->grouper_info->g_v6_mask[NPC_GPR_SPORT_OFF_v6 + 1] = mask & 0xFF;
}

static void
npf_grouper_add_dst_port(struct npf_rule_ctx *ctx, uint16_t match,
			 uint16_t mask)
{
	if (ctx->grouper_flags & GPR_SET_DST_PORT) {
		match = 0;
		mask = NPF_MATCH_ALL_MASK16;
	}
	ctx->grouper_flags |= GPR_SET_DST_PORT;

	ctx->grouper_info->g_v4_match[NPC_GPR_DPORT_OFF_v4] = match >> 8;
	ctx->grouper_info->g_v4_match[NPC_GPR_DPORT_OFF_v4 + 1] = match & 0xFF;
	ctx->grouper_info->g_v4_mask[NPC_GPR_DPORT_OFF_v4] = mask >> 8;
	ctx->grouper_info->g_v4_mask[NPC_GPR_DPORT_OFF_v4 + 1] = mask & 0xFF;

	ctx->grouper_info->g_v6_match[NPC_GPR_DPORT_OFF_v6] = match >> 8;
	ctx->grouper_info->g_v6_match[NPC_GPR_DPORT_OFF_v6 + 1] = match & 0xFF;
	ctx->grouper_info->g_v6_mask[NPC_GPR_DPORT_OFF_v6] = mask >> 8;
	ctx->grouper_info->g_v6_mask[NPC_GPR_DPORT_OFF_v6 + 1] = mask & 0xFF;
}

static void
npf_grouper_add_port(struct npf_rule_ctx *ctx, int options, uint16_t match,
			 uint16_t mask)
{
	if (options & NC_MATCH_SRC)
		npf_grouper_add_src_port(ctx, match, mask);
	else
		npf_grouper_add_dst_port(ctx, match, mask);
}

static void
npf_grouper_add_icmpv4_type_code(struct npf_rule_ctx *ctx, bool class,
				 int type, int code)
{
	if (class || (ctx->grouper_flags & GPR_SET_ICMPV4_TYPE_CODE)) {
		type = -1;
		code = -1;
	}
	ctx->grouper_flags |= GPR_SET_ICMPV4_TYPE_CODE;

	ctx->grouper_info->g_v4_match[NPC_GPR_ICMPTYPE_OFF_v4] =
		(type == -1) ? 0 : type;
	ctx->grouper_info->g_v4_mask[NPC_GPR_ICMPTYPE_OFF_v4] =
		(type == -1) ? NPF_MATCH_ALL_MASK8 : 0;
	ctx->grouper_info->g_v4_match[NPC_GPR_ICMPCODE_OFF_v4] =
		(code == -1) ? 0 : code;
	ctx->grouper_info->g_v4_mask[NPC_GPR_ICMPCODE_OFF_v4] =
		(code == -1) ? NPF_MATCH_ALL_MASK8 : 0;
}

static void
npf_grouper_add_icmpv6_type_code(struct npf_rule_ctx *ctx, bool class,
				 int type, int code)
{
	if (class || (ctx->grouper_flags & GPR_SET_ICMPV6_TYPE_CODE)) {
		type = -1;
		code = -1;
	}
	ctx->grouper_flags |= GPR_SET_ICMPV6_TYPE_CODE;

	ctx->grouper_info->g_v6_match[NPC_GPR_ICMPTYPE_OFF_v6] =
		(type == -1) ? 0 : type;
	ctx->grouper_info->g_v6_mask[NPC_GPR_ICMPTYPE_OFF_v6] =
		(type == -1) ? NPF_MATCH_ALL_MASK8 : 0;
	ctx->grouper_info->g_v6_match[NPC_GPR_ICMPCODE_OFF_v6] =
		(code == -1) ? 0 : code;
	ctx->grouper_info->g_v6_mask[NPC_GPR_ICMPCODE_OFF_v6] =
		(code == -1) ? NPF_MATCH_ALL_MASK8 : 0;
}

static void
npf_grouper_add_icmp_type_code(struct npf_rule_ctx *ctx, int options,
			       bool class, int type, int code)
{
	if (options & NC_MATCH_ICMP)
		npf_grouper_add_icmpv4_type_code(ctx, class, type, code);
	else
		npf_grouper_add_icmpv6_type_code(ctx, class, type, code);
}

static int
npf_gen_tcp_flag(char *flagval, uint8_t *flags, uint8_t *mask)
{
	bool not;
	uint flag = 0;

	if (flagval[0] == '!') {
		not = true;
		flagval++;
	} else
		not = false;

	if (strcmp(flagval, "SYN") == 0)
		flag = TH_SYN;
	else if (strcmp(flagval, "ACK") == 0)
		flag = TH_ACK;
	else if (strcmp(flagval, "FIN") == 0)
		flag = TH_FIN;
	else if (strcmp(flagval, "RST") == 0)
		flag = TH_RST;
	else if (strcmp(flagval, "PSH") == 0)
		flag = TH_PUSH;
	else if (strcmp(flagval, "URG") == 0)
		flag = TH_URG;
	else
		return -EINVAL;

	if (!not)
		*flags |= flag;
	*mask |= flag;

	return 0;
}

static int
npf_gen_ncode_tcp_flags(nc_ctx_t *nc_ctx, char *tcp_flags)
{
	uint8_t flags = 0;
	uint8_t mask = 0;

	/* This parses: [!]<flag>[,[!]<flag>]* */
	char *flagval;
	char *tmp_value = tcp_flags;

	while ((flagval = strsep(&tmp_value, ",")) != NULL) {
		int ret = npf_gen_tcp_flag(flagval, &flags, &mask);
		if (tmp_value)
			tmp_value[-1] = ','; /* revert to ',' from '\0' */
		if (ret) {
			RTE_LOG(ERR, FIREWALL, "NPF: unexpected value in rule: "
				"tcp-flags=%s\n", tcp_flags);
			return ret;
		}
	}

	npf_gennc_tcpfl(nc_ctx, flags, mask);
	return 0;
}

static int
npf_gen_ncode_mac_addr(nc_ctx_t *nc_ctx, char *value, int options)
{
	struct rte_ether_addr ma;
	uint8_t *ab = ma.addr_bytes;

	if (sscanf(value, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
		   ab, ab + 1, ab + 2, ab + 3, ab + 4, ab + 5) != 6) {
		RTE_LOG(ERR, FIREWALL, "NPF: unexpected value in rule: "
			" %s-mac=%s\n",
			(options & NC_MATCH_SRC) ? "src" : "dst", value);
		return -EINVAL;
	}

	npf_gennc_mac_addr(nc_ctx, options, &ma);

	return 0;
}

int
npf_parse_ip_addr(char *value, sa_family_t *fam, npf_addr_t *addr,
		  npf_netmask_t *masklen, bool *negate)
{
	char *slash = strchr(value, '/');
	char *masklen_str = NULL;
	unsigned long ulong_masklen;
	unsigned long max_masklen;
	int ret;

	if (value[0] == '!') {
		*negate = true;
		value++;
	} else
		*negate = false;

	if (slash) {
		*slash = '\0';
		masklen_str = slash + 1;
	}

	if (strchr(value, ':')) {
		*fam = AF_INET6;
		max_masklen = 128;
	} else {
		*fam = AF_INET;
		max_masklen = 32;
	}

	ret = inet_pton(*fam, value, addr);
	if (slash)
		*slash = '/';	/* put slash back to restore original value */
	if (ret != 1)
		return -EINVAL;

	if (masklen_str) {
		char *endp;
		ulong_masklen = strtoul(masklen_str, &endp, 10);
		if (endp == masklen_str || ulong_masklen > max_masklen)
			return -EINVAL;
		*masklen = ulong_masklen;
	} else
		*masklen = NPF_NO_NETMASK;

	return 0;
}

static void
npf_masklen_to_grouper_mask(sa_family_t fam, npf_netmask_t masklen,
			    npf_addr_t *addr_mask)
{
	memset(addr_mask, 0xFF, sizeof(*addr_mask));
	if (fam == AF_INET) {
		if (masklen == NPF_NO_NETMASK)
			masklen = 32;
		addr_mask->s6_addr32[0] =
			htonl(npf_prefix_to_host_mask4(masklen));
	} else {
		int i, j;

		if (masklen == NPF_NO_NETMASK)
			masklen = 128;
		for (i = masklen, j = 0; i > 0; i -= 8, j++) {
			if (i >= 8)
				addr_mask->s6_addr[j] = 0x00;
			else
				addr_mask->s6_addr[j] =
					(unsigned long)((1 << (8 - i)) - 1);
		}
	}
}


static int
npf_gen_ncode_ip_addr(struct npf_rule_ctx *ctx, char *value, int options)
{
	sa_family_t fam;
	npf_addr_t addr;
	npf_addr_t addr_mask;
	npf_netmask_t masklen;
	bool negate;
	int ret = npf_parse_ip_addr(value, &fam, &addr, &masklen, &negate);

	if (ret) {
		RTE_LOG(ERR, FIREWALL, "NPF: unexpected value in rule: "
			"%s-addr=%s\n",
			(options & NC_MATCH_SRC) ? "src" : "dst", value);
		return ret;
	}

	if (fam != AF_INET && fam != AF_INET6) {
		RTE_LOG(ERR, FIREWALL, "NPF: unexpected family %u from rule: "
			"%s-addr=%s\n", fam,
			(options & NC_MATCH_SRC) ? "src" : "dst", value);
		return -EINVAL;
	}

	ctx->grouper_info->g_family = fam;

	if (negate) {
		options |= NC_MATCH_INVERT;
		/* Grouper matches all for negation. */
		npf_grouper_add_ip_addr(ctx, options, NULL, NULL);
	} else {
		/*
		 * When mask length is 0 generate an address-family
		 * instruction instead of address. Only do if not negated
		 * as currently it does not support negated.
		 */
		if (masklen == 0) {
			npf_gennc_addrfamily(ctx->nc_ctx, fam);
			npf_grouper_add_ip_addr(ctx, options, NULL, NULL);
			return 0;
		}
	}

	if (fam == AF_INET)
		npf_gennc_v4cidr(ctx->nc_ctx, options, &addr, masklen);
	else
		npf_gennc_v6cidr(ctx->nc_ctx, options, &addr, masklen);

	npf_masklen_to_grouper_mask(fam, masklen, &addr_mask);
	/*
	 * NB - npf_grouper_add_ip_addr() is called above due to an invert,
	 * this will not override it, as subsequent calls will result
	 * in matching all.
	 */
	npf_grouper_add_ip_addr(ctx, options, addr.s6_addr, addr_mask.s6_addr);

	return 0;
}

static int
npf_gen_ncode_ip_addr_group(nc_ctx_t *nc_ctx, char *value, int options)
{
	uint32_t tid;
	int ret = npf_addrgrp_name2tid(value, &tid);

	if (ret) {
		RTE_LOG(ERR, FIREWALL, "NPF: unknown address group in rule: "
			"%s-addr-group=%s\n",
			(options & NC_MATCH_SRC) ? "src" : "dst", value);
		return ret;
	}

	npf_gennc_tbl(nc_ctx, options, tid);
	return 0;
}

static int
npf_gen_ncode_port(struct npf_rule_ctx *ctx, char *value, int options)
{
	char *dash = strchr(value, '-');
	char *low_port_str = value;
	char *high_port_str = NULL;
	char *endp;
	unsigned long low_port, high_port;

	if (dash) {
		*dash = '\0';
		high_port_str = dash + 1;
	}

	low_port = strtoul(low_port_str, &endp, 10);
	if (dash)
		*dash = '-';	/* put dash back so error msg is complete */
	if (endp == low_port_str || low_port > 0xFFFF)
		return -EINVAL;

	if (high_port_str) {
		high_port = strtoul(high_port_str, &endp, 10);
		if (endp == high_port_str || high_port > 0xFFFF)
			return -EINVAL;
	} else
		high_port = low_port;

	npf_gennc_ports(ctx->nc_ctx, options, low_port, high_port);
	if (low_port == high_port)
		npf_grouper_add_port(ctx, options, low_port, 0);
	else
		npf_grouper_add_port(ctx, options, 0, NPF_MATCH_ALL_MASK16);

	return 0;
}

/*
 * Note that this is used for both setting ports directly and for
 * resource groups, so it is flexible to support multiple entries
 * (separated by semi-colons), and port ranges (separated by a hyphen).
 *
 * If ncode_group is true, then request the ncode to OR the entries.
 * If not done in this function, then it should be done by the calling
 * function, if more than one entry.
 */
static int
npf_gen_ncode_port_list(struct npf_rule_ctx *ctx, char *value, int options,
			bool ncode_group)
{
	char *portval;
	char *tmp_value = value;

	if (ncode_group)
		npf_ncgen_group(ctx->nc_ctx); /* start group of ORed ports */

	while ((portval = strsep(&tmp_value, ";")) != NULL) {
		int ret = npf_gen_ncode_port(ctx, portval, options);
		if (tmp_value)
			tmp_value[-1] = ';'; /* revert to ';' from '\0' */
		if (ret) {
			RTE_LOG(ERR, FIREWALL, "NPF: unexpected value in rule: "
				"%s-port=%s\n", (options & NC_MATCH_SRC) ?
				"src" : "dst", value);
			return ret;
		}
	}

	if (ncode_group)
		/* fix-up jumps for ORed ports */
		npf_ncgen_endgroup(ctx->nc_ctx);

	return 0;
}

struct group_cb_info {
	struct npf_rule_ctx *ctx;
	int options;
	int rule_count;
	int error;
};

/*
 * This is called back for each rule line in the resource group matching
 * the name.
 */
static bool
npf_gen_ncode_port_line_cb(void *param, struct npf_cfg_rule_walk_state *state)
{
	struct group_cb_info *info = param;
	/* dup the rule, as may change bytes while parsing */
	char *rule = strdupa(state->rule);
	int ret = npf_gen_ncode_port_list(info->ctx, rule,
						      info->options, false);
	if (ret) {
		RTE_LOG(ERR, FIREWALL, "NPF: above error from port group "
			"contents in rule: %s-port-group=%s\n",
			(info->options & NC_MATCH_SRC) ? "src" : "dst",
			state->group);
		info->error = ret;
		return false;
	}
	info->rule_count++;
	return true;
}

static int
npf_gen_ncode_port_group(struct npf_rule_ctx *ctx, char *value,
				     int options)
{
	struct group_cb_info info = {
		.ctx = ctx,
		.options = options,
		.rule_count = 0,
		.error = 0.
	};

	/*
	 * Currently the ports should be in a single rule entry, but there
	 * is support for the ports being across multiple rules, as could
	 * change in future.
	 */
	npf_ncgen_group(ctx->nc_ctx);     /* start group of ORed ports */

	npf_cfg_rule_group_walk(NPF_RULE_CLASS_PORT_GROUP, value, &info,
				npf_gen_ncode_port_line_cb);

	/* fix-up jumps for ORed ports */
	npf_ncgen_endgroup(ctx->nc_ctx);

	if (info.error)
		return info.error;

	if (info.rule_count == 0)
		RTE_LOG(WARNING, FIREWALL, "NPF: unknown or empty port group "
			"in rule: %s-port-group=%s\n",
			(options & NC_MATCH_SRC) ? "src" : "dst", value);

	return 0;
}

struct npf_icmp_name_table {
	const char *name;
	int type;
	int code;
};

struct npf_icmp_name_table icmpv4_name_table[] = {
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
	{ NULL }
};

struct npf_icmp_name_table icmpv6_name_table[] = {
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
	{ NULL }
};

static int
npf_gen_ncode_icmp_name(struct npf_rule_ctx *ctx, char *value,
				    int options)
{
	struct npf_icmp_name_table *table = (options & NC_MATCH_ICMP) ?
		icmpv4_name_table : icmpv6_name_table;
	struct npf_icmp_name_table *entry;

	for (entry = table; entry->name; entry++) {
		if (strcmp(value, entry->name) == 0) {
			npf_gennc_icmp(ctx->nc_ctx, entry->type, entry->code,
				       (options & NC_MATCH_ICMP) != 0, false);
			npf_grouper_add_icmp_type_code(ctx, options, false,
						       entry->type,
						       entry->code);
			return 0;
		}
	}

	return -EINVAL;
}

static int
npf_gen_ncode_icmp(struct npf_rule_ctx *ctx, char *value,
			       int options)
{
	char *colon;
	char *type_str = value;
	char *code_str = NULL;
	char *endp;
	long type, code;

	if (!isdigit(value[0]))
		return npf_gen_ncode_icmp_name(ctx, value, options);

	colon = strchr(value, ':');
	if (colon) {
		*colon = '\0';
		code_str = colon + 1;
	}

	type = strtol(type_str, &endp, 10);
	if (colon)
		*colon = ':';	/* put colon back so error msg is complete */
	if (endp == type_str || type > 255)
		return -EINVAL;

	if (code_str) {
		code = strtol(code_str, &endp, 10);
		if (endp == code_str || code > 255)
			return -EINVAL;
	} else
		code = -1;

	npf_gennc_icmp(ctx->nc_ctx, type, code,
		       (options & NC_MATCH_ICMP) != 0, false);
	npf_grouper_add_icmp_type_code(ctx, options, false, type, code);

	return 0;
}

static int
npf_gen_ncode_icmp_class(struct npf_rule_ctx *ctx, char *value, int options)
{
	bool error = false;

	if (strcmp(value, "error") == 0) {
		error = true;
	} else if (strcmp(value, "info") != 0) {
		RTE_LOG(ERR, FIREWALL, "NPF: unexpected value in rule: "
			"icmpv%s-class=%s\n",
			(options & NC_MATCH_ICMP) ? "4" : "6", value);
		return -EINVAL;
	}

	npf_gennc_icmp(ctx->nc_ctx, error, 0,
		       (options & NC_MATCH_ICMP) != 0, true);

	/*
	 * For IPv4, grouper can not help.
	 * For IPv6, grouper eventually will help.
	 */
	npf_grouper_add_icmp_type_code(ctx, options, true,
				       error ? 0 : ICMP6_INFOMSG_MASK, 0);

	return 0;
}

/*
 * Note that this is used for both setting icmp types/codes directly and
 * for resource groups, so it is flexible to support multiple entries
 * (separated by semi-colons), and type and optional code (separated by
 * a colon).
 *
 * If ncode_group is true, then request the ncode to OR the entries.
 * If not done in this function, then it should be done by the calling
 * function, if more than one entry.
 */
static int
npf_gen_ncode_icmp_list(struct npf_rule_ctx *ctx, char *value, int options,
			bool ncode_group)
{
	char *icmpval;
	char *tmp_value = value;

	if (ncode_group)
		npf_ncgen_group(ctx->nc_ctx); /* start group of ORed types */

	while ((icmpval = strsep(&tmp_value, ";")) != NULL) {
		int ret = npf_gen_ncode_icmp(ctx, icmpval, options);
		if (tmp_value)
			tmp_value[-1] = ';'; /* revert to ';' from '\0' */
		if (ret) {
			RTE_LOG(ERR, FIREWALL, "NPF: unexpected value in rule: "
				"icmpv%s-port=%s\n",
				(options & NC_MATCH_ICMP) ? "4" : "6", value);
			return ret;
		}
	}

	if (ncode_group)
		/* fix-up jumps for ORed types */
		npf_ncgen_endgroup(ctx->nc_ctx);

	return 0;
}

/*
 * This is called back for each rule line in the resource group matching
 * the name.
 */
static bool
npf_gen_ncode_icmp_line_cb(void *param, struct npf_cfg_rule_walk_state *state)
{
	struct group_cb_info *info = param;
	/* dup the rule, as may change bytes while parsing */
	char *rule = strdupa(state->rule);
	int ret = npf_gen_ncode_icmp_list(info->ctx, rule, info->options,
					  false);
	if (ret) {
		RTE_LOG(ERR, FIREWALL, "NPF: above error from icmp group "
			"contents in rule: icmpv%s-group=%s\n",
			(info->options & NC_MATCH_ICMP) ? "4" : "6",
			state->group);
		info->error = ret;
		return false;
	}
	info->rule_count++;
	return true;
}

static int
npf_gen_ncode_icmp_group(struct npf_rule_ctx *ctx, char *value,
				     int options)
{
	struct group_cb_info info = {
		.ctx = ctx,
		.options = options,
		.rule_count = 0,
		.error = 0.
	};
	enum npf_rule_class group_class = (options & NC_MATCH_ICMP) ?
		NPF_RULE_CLASS_ICMP_GROUP : NPF_RULE_CLASS_ICMPV6_GROUP;

	/*
	 * Currently the types should be in a single rule entry, but there
	 * is support for the types being across multiple rules, as could
	 * change in future.
	 */
	npf_ncgen_group(ctx->nc_ctx);     /* start group of ORed types */

	npf_cfg_rule_group_walk(group_class, value, &info,
				npf_gen_ncode_icmp_line_cb);

	npf_ncgen_endgroup(ctx->nc_ctx);  /* fix-up jumps for ORed types */

	if (info.error)
		return info.error;

	if (info.rule_count == 0)
		RTE_LOG(WARNING, FIREWALL, "NPF: unknown or empty icmp group "
			"in rule: icmpv%s-group=%s\n",
			(options & NC_MATCH_ICMP) ? "4" : "6", value);

	return 0;
}

/*
 * Note that this is used for both setting DSCP values directly and
 * for resource groups, so it is flexible to support multiple entries
 * (separated by semi-colons).
 */
static int
npf_parse_dscp_list(uint64_t *dscp_set, char *value)
{
	char *dscpval;
	char *tmp_value = value;

	while ((dscpval = strsep(&tmp_value, ";")) != NULL) {
		char *endp;
		unsigned long dscp = strtoul(dscpval, &endp, 10);
		if (tmp_value)
			tmp_value[-1] = ';'; /* revert to ';' from '\0' */
		if (endp == dscpval || dscp > DSCP_MAX) {
			RTE_LOG(ERR, FIREWALL, "NPF: unexpected value in rule: "
				"dscp=%s\n", value);
			return -EINVAL;
		}
		*dscp_set |= (1ul << dscp);
	}

	return 0;
}

/*
 * Holds information passed in for each line in the resource group.
 */
struct dscp_cb_info {
	uint64_t dscp_set;
	int rule_count;
	int error;
};

/*
 * This is called back for each rule line in the resource group matching
 * the name.
 */
static bool
npf_gen_ncode_dscp_line_cb(void *param, struct npf_cfg_rule_walk_state *state)
{
	struct dscp_cb_info *info = param;
	/* dup the rule, as may change bytes while parsing */
	char *rule = strdupa(state->rule);
	int ret = npf_parse_dscp_list(&info->dscp_set, rule);

	if (ret) {
		RTE_LOG(ERR, FIREWALL, "NPF: above error from dscp group "
			"contents in rule: dscp-group=%s\n", state->group);
		info->error = ret;
		return false;
	}
	info->rule_count++;
	return true;
}

int
npf_dscp_group_getmask(char *group_name, uint64_t *dscp_set)
{
	struct dscp_cb_info info = {
		.dscp_set = 0,
		.rule_count = 0,
		.error = 0,
	};

	/*
	 * Currently the types should be in a single rule entry, but there
	 * is support for the types being across multiple rules, as could
	 * change in future.
	 */

	npf_cfg_rule_group_walk(NPF_RULE_CLASS_DSCP_GROUP, group_name, &info,
				npf_gen_ncode_dscp_line_cb);

	if (!info.error)
		*dscp_set = info.dscp_set;


	if (info.rule_count == 0)
		RTE_LOG(WARNING, FIREWALL, "NPF: unknown or empty dscp group "
			"in rule: dscp-group=%s\n", group_name);

	return info.error;
}

static int
npf_gen_ncode_dscp_group(struct npf_rule_ctx *ctx, char *value)
{
	int err;
	uint64_t dscp_set = 0UL;

	err = npf_dscp_group_getmask(value, &dscp_set);
	if (err)
		return err;

	npf_ncgen_matchdscp(ctx->nc_ctx, dscp_set);

	return 0;
}

static int
npf_gen_ncode_protocol_list(struct npf_rule_ctx *ctx, char *value)
{
	char *protostr;
	char *tmp_value = value;

	while ((protostr = strsep(&tmp_value, ";")) != NULL) {
		char *endp;
		unsigned long proto = strtoul(protostr, &endp, 10);
		if (tmp_value)
			tmp_value[-1] = ';'; /* revert to ';' from '\0' */
		if (endp == value || proto > 255) {
			RTE_LOG(ERR, FIREWALL, "NPF: unexpected value in rule: "
				"proto=%s\n", value);
			return -EINVAL;
		}
		npf_grouper_add_proto(ctx, proto, 0);
		npf_gennc_proto_final(ctx->nc_ctx, proto);
	}

	return 0;
}

/*
 * This is called back for each rule line in the resource group matching
 * the name.
 */
static bool
npf_gen_ncode_protocol_line_cb(void *param,
			       struct npf_cfg_rule_walk_state *state)
{
	struct group_cb_info *info = param;
	/* dup the rule, as may change bytes while parsing */
	char *rule = strdupa(state->rule);
	int ret = npf_gen_ncode_protocol_list(info->ctx, rule);
	if (ret) {
		RTE_LOG(ERR, FIREWALL, "NPF: above error from protocol group "
			"contents in rule: protocol-group=%s\n", state->group);
		info->error = ret;
		return false;
	}
	info->rule_count++;
	return true;
}

static int
npf_gen_ncode_protocol_group(struct npf_rule_ctx *ctx, char *value)
{
	struct group_cb_info info = {
		.ctx = ctx,
		.rule_count = 0,
		.error = 0.
	};

	/*
	 * Currently the protocols should be in a single rule entry, but there
	 * is support for the protocols being across multiple rules, as could
	 * change in future.
	 */
	npf_ncgen_group(ctx->nc_ctx);     /* start group of ORed protocols */

	npf_cfg_rule_group_walk(NPF_RULE_CLASS_PROTOCOL_GROUP, value, &info,
				npf_gen_ncode_protocol_line_cb);

	/* fix-up jumps for ORed protocols */
	npf_ncgen_endgroup(ctx->nc_ctx);

	if (info.error)
		return info.error;

	if (info.rule_count == 0)
		RTE_LOG(WARNING, FIREWALL, "NPF: unknown or empty protocol "
			"group in rule: protocol-group=%s\n", value);

	return 0;
}

int
npf_gen_ncode(zhashx_t *config_ht, void **ncode, uint32_t *size,
	      bool any_match_rprocs,
	      struct npf_rule_grouper_info *grouper_info)
{
	char *src_addr, *src_addr_group, *dst_addr, *dst_addr_group;
	char *tcp_flags, *ipv6_route;
	char *value;
	int err;
	struct npf_rule_ctx ctx;

	ctx.grouper_info = grouper_info;

	err = npf_initialise_ctx(&ctx);
	if (err)
		goto error;

	src_addr = zhashx_lookup(config_ht, "src-addr");
	src_addr_group = zhashx_lookup(config_ht, "src-addr-group");
	dst_addr = zhashx_lookup(config_ht, "dst-addr");
	dst_addr_group = zhashx_lookup(config_ht, "dst-addr-group");

	/*
	 * Handle address family
	 */
	value = zhashx_lookup(config_ht, "family");
	if (value) {
		sa_family_t family;

		if (strcmp(value, "inet") == 0)
			family = AF_INET;
		else if (strcmp(value, "inet6") == 0)
			family = AF_INET6;
		else {
			RTE_LOG(ERR, FIREWALL, "NPF: unexpected value in rule: "
				"family=%s\n", value);
			err = -EINVAL;
			goto error;
		}

		npf_gennc_addrfamily(ctx.nc_ctx, family);
		ctx.grouper_info->g_family = family;
	}

	tcp_flags = zhashx_lookup(config_ht, "tcp-flags");
	ipv6_route = zhashx_lookup(config_ht, "ipv6-route");

	/*
	 * Handle final protocol (in extension chain)
	 */
	char const *proto_key = "proto-final";
	value = zhashx_lookup(config_ht, proto_key);
	if (!value) {
		proto_key = "proto";
		value = zhashx_lookup(config_ht, proto_key);
	}
	if (value) {
		char *endp;
		unsigned long proto = strtoul(value, &endp, 10);
		if (endp == value || proto > 255) {
			RTE_LOG(ERR, FIREWALL, "NPF: unexpected value in rule: "
				"%s=%s\n", proto_key, value);
			err = -EINVAL;
			goto error;
		}

		npf_grouper_add_proto(&ctx, proto, 0);
		/*
		 * Protocol check is done in the TCP flags ncode
		 */
		if (!tcp_flags)
			npf_gennc_proto_final(ctx.nc_ctx, proto);
	}

	/*
	 * Handle base protocol in IP header
	 */
	value = zhashx_lookup(config_ht, "proto-base");
	if (value) {
		char *endp;
		unsigned long proto_base = strtoul(value, &endp, 10);
		if (endp == value || proto_base > 255) {
			RTE_LOG(ERR, FIREWALL, "NPF: unexpected value in rule: "
				"proto-base=%s\n", value);
			err = -EINVAL;
			goto error;
		}
		npf_gennc_proto_base(ctx.nc_ctx, proto_base);
	}

	value = zhashx_lookup(config_ht, "protocol-group");
	if (value) {
		err = npf_gen_ncode_protocol_group(&ctx, value);
		if (err)
			goto error;
	}

	/*
	 * Handle TTL match
	 */
	char *ttl_str = zhashx_lookup(config_ht, "ttl");
	if (ttl_str) {
		char *endp;
		unsigned long ttl_val = strtoul(ttl_str, &endp, 10);
		if (endp == ttl_str || ttl_val > 255) {
			RTE_LOG(ERR, FIREWALL, "NPF: unexpected value in rule: "
				"ttl=%s\n", ttl_str);
			err = -EINVAL;
			goto error;
		}

		npf_gennc_ttl(ctx.nc_ctx, ttl_val);
	}

	/*
	 * Handle TCP flags
	 */
	if (tcp_flags) {
		err = npf_gen_ncode_tcp_flags(ctx.nc_ctx, tcp_flags);
		if (err)
			goto error;
	}

	/*
	 * Handle IPv6 Route
	 */
	if (ipv6_route) {
		char *endp;
		unsigned long type = strtoul(ipv6_route, &endp, 10);
		if (endp == ipv6_route || type > 255) {
			RTE_LOG(ERR, FIREWALL, "NPF: unexpected value in rule: "
				"ipv6-route=%s\n", ipv6_route);
			err = -EINVAL;
			goto error;
		}

		npf_gennc_ip6_rt(ctx.nc_ctx, type);
	}

	/*
	 * Handle MAC addresses
	 */
	value = zhashx_lookup(config_ht, "src-mac");
	if (value) {
		err = npf_gen_ncode_mac_addr(ctx.nc_ctx, value, NC_MATCH_SRC);
		if (err)
			goto error;
	}
	value = zhashx_lookup(config_ht, "dst-mac");
	if (value) {
		err = npf_gen_ncode_mac_addr(ctx.nc_ctx, value, 0);
		if (err)
			goto error;
	}

	/*
	 * Handle IP addresses
	 */
	if (src_addr) {
		err = npf_gen_ncode_ip_addr(&ctx, src_addr, NC_MATCH_SRC);
		if (err)
			goto error;
	}

	if (src_addr_group) {
		err = npf_gen_ncode_ip_addr_group(ctx.nc_ctx, src_addr_group,
						  NC_MATCH_SRC);
		if (err)
			goto error;
	}
	if (dst_addr) {
		err = npf_gen_ncode_ip_addr(&ctx, dst_addr, 0);
		if (err)
			goto error;
	}

	if (dst_addr_group) {
		err = npf_gen_ncode_ip_addr_group(ctx.nc_ctx, dst_addr_group,
						  0);
		if (err)
			goto error;
	}

	/*
	 * Handle ports
	 */
	value = zhashx_lookup(config_ht, "src-port");
	if (value) {
		err = npf_gen_ncode_port_list(&ctx, value, NC_MATCH_SRC, true);
		if (err)
			goto error;
	}
	value = zhashx_lookup(config_ht, "src-port-group");
	if (value) {
		err = npf_gen_ncode_port_group(&ctx, value, NC_MATCH_SRC);
		if (err)
			goto error;
	}

	value = zhashx_lookup(config_ht, "dst-port");
	if (value) {
		err = npf_gen_ncode_port_list(&ctx, value, 0, true);
		if (err)
			goto error;
	}
	value = zhashx_lookup(config_ht, "dst-port-group");
	if (value) {
		err = npf_gen_ncode_port_group(&ctx, value, 0);
		if (err)
			goto error;
	}

	/*
	 * Handle ICMP types and codes
	 */
	value = zhashx_lookup(config_ht, "icmpv4");
	if (value) {
		err = npf_gen_ncode_icmp_list(&ctx, value,
							  NC_MATCH_ICMP, true);
		if (err)
			goto error;
	}
	value = zhashx_lookup(config_ht, "icmpv4-group");
	if (value) {
		err = npf_gen_ncode_icmp_group(&ctx, value,
							   NC_MATCH_ICMP);
		if (err)
			goto error;
	}
	value = zhashx_lookup(config_ht, "icmpv6");
	if (value) {
		err = npf_gen_ncode_icmp_list(&ctx, value,
							  NC_MATCH_ICMP6, true);
		if (err)
			goto error;
	}
	value = zhashx_lookup(config_ht, "icmpv6-class");
	if (value) {
		err = npf_gen_ncode_icmp_class(&ctx, value, NC_MATCH_ICMP6);
		if (err)
			goto error;
	}
	value = zhashx_lookup(config_ht, "icmpv6-group");
	if (value) {
		err = npf_gen_ncode_icmp_group(&ctx, value,
							   NC_MATCH_ICMP6);
		if (err)
			goto error;
	}

	/*
	 * Handle DSCP
	 */
	value = zhashx_lookup(config_ht, "dscp");
	if (value) {
		uint64_t dscp_set = 0;

		err = npf_parse_dscp_list(&dscp_set, value);
		if (err)
			goto error;

		npf_ncgen_matchdscp(ctx.nc_ctx, dscp_set);
	}
	value = zhashx_lookup(config_ht, "dscp-group");
	if (value) {
		err = npf_gen_ncode_dscp_group(&ctx, value);
		if (err)
			goto error;
	}

	/*
	 * Handle Fragment
	 */
	value = zhashx_lookup(config_ht, "fragment");
	if (value) {
		bool frag;

		if (strcmp(value, "y") == 0)
			frag = true;
		else if (strcmp(value, "n") == 0)
			frag = false;
		else {
			RTE_LOG(ERR, FIREWALL, "NPF: unexpected value in rule: "
				"fragment=%s\n", value);
			err = -EINVAL;
			goto error;
		}

		if (frag)
			npf_gennc_ip_frag(ctx.nc_ctx);
	}

	/*
	 * Handle PCP
	 */
	value = zhashx_lookup(config_ht, "pcp");
	if (value) {
		char *endp;
		unsigned long pcp = strtoul(value, &endp, 10);
		if (endp == value || pcp > 7) {
			RTE_LOG(ERR, FIREWALL, "NPF: unexpected value in rule: "
				"pcp=%s\n", value);
			err = -EINVAL;
			goto error;
		}

		npf_gennc_etherpcp(ctx.nc_ctx, pcp);
	}

	/*
	 * Handle Ether type
	 */
	value = zhashx_lookup(config_ht, "ether-type");
	if (value) {
		char *endp;
		unsigned long type = strtoul(value, &endp, 10);
		if (endp == value || type > 0xFFFF) {
			RTE_LOG(ERR, FIREWALL, "NPF: unexpected value in rule: "
				"ether-type=%s\n", value);
			err = -EINVAL;
			goto error;
		}

		npf_gennc_ethertype(ctx.nc_ctx, type);
	}

	/*
	 * Handle rproc match functions - this is only added if at least
	 * one rproc has a "match" function.
	 */
	if (any_match_rprocs)
		npf_gennc_rproc(ctx.nc_ctx, NULL);

	/*
	 * Complete the ncode (if there is any).
	 */
	if (npf_ncgen_size(ctx.nc_ctx)) {
		*ncode = npf_ncgen_complete(ctx.nc_ctx, size);
		ctx.nc_ctx = NULL;

		if (!*ncode || !*size) {
			RTE_LOG(ERR, FIREWALL, "failed to generate ncode\n");
			return -ENOMEM;
		}
	} else {
		/*
		 * Optimise case of having no rules by having no ncode.
		 */
		npf_ncgen_free(ctx.nc_ctx);
		ctx.nc_ctx = NULL;
		*ncode = NULL;
		*size = 0;
	}

	return 0;

error:
	npf_ncgen_free(ctx.nc_ctx);
	return err;
}

static int
npf_process_nat_port(in_port_t *tport, in_port_t *tport_stop, char *value)
{
	char *dash = strchr(value, '-');
	char *low_port_str = value;
	char *high_port_str = NULL;
	char *endp;
	unsigned long low_port, high_port;

	if (dash) {
		*dash = '\0';
		high_port_str = dash + 1;
	}

	low_port = strtoul(low_port_str, &endp, 10);
	if (dash)
		*dash = '-';	/* put dash back so error msg is complete */
	if (endp == low_port_str || low_port > 0xFFFF)
		return -EINVAL;

	if (high_port_str) {
		high_port = strtoul(high_port_str, &endp, 10);
		if (endp == high_port_str || high_port > 0xFFFF)
			return -EINVAL;
	} else
		high_port = low_port;

	*tport = low_port;
	*tport_stop = high_port;

	return 0;
}

static int
npf_process_nat_ip_masq(uint32_t *flags, uint8_t *addr_sz, npf_addr_t *taddr,
			npf_addr_t *taddr_stop, npf_rule_t *rl)
{
	enum npf_attach_type attach_type;
	const char *attach_point;
	int ret = npf_rule_get_attach_point(rl, &attach_type, &attach_point);
	struct ifnet *ifp;
	struct if_addr *ifa;

	if (ret) {
		RTE_LOG(ERR, FIREWALL, "masquerade: failed to find attach "
			"point for rule\n");
		return -ENOENT;
	}

	if (attach_type != NPF_ATTACH_TYPE_INTERFACE) {
		RTE_LOG(ERR, FIREWALL, "masquerade: non-interface "
			"attach point %u\n", attach_type);
		return -EINVAL;
	}

	*flags |= NPF_NAT_MASQ;
	*addr_sz = 4;

	ifp = dp_ifnet_byifname(attach_point);
	if (!ifp) {
		RTE_LOG(ERR, FIREWALL, "masquerade: interface \"%s\" does "
			"not exist\n", attach_point);
		return -ENOENT;
	}

	if ((ifp->if_flags & IFF_UP) == 0)
		RTE_LOG(WARNING, FIREWALL, "masquerade: interface '%s' "
			"is down\n", attach_point);

	cds_list_for_each_entry(ifa, &ifp->if_addrhead, ifa_link) {
		struct sockaddr_storage *ss = &ifa->ifa_addr;
		struct sockaddr_in *sin;

		if (ss->ss_family == AF_INET) {
			sin = (struct sockaddr_in *)ss;
			memcpy(taddr, &sin->sin_addr, *addr_sz);
			*taddr_stop = *taddr;
			return 0;
		}
	}

	RTE_LOG(WARNING, FIREWALL,
		"masquerade: IPv4 address not found for %s\n", attach_point);

	/* Set address to 0 - it will be updated if an address is provided. */
	memset(taddr, 0, *addr_sz);
	*taddr_stop = *taddr;

	return 0;
}

static int
npf_process_nat_ip_addr(uint8_t *addr_sz, npf_addr_t *taddr,
			npf_addr_t *taddr_stop, const char *value)
{
	char *dash = strchr(value, '-');
	const char *low_ip_addr_str = value;
	char *high_ip_addr_str = NULL;
	sa_family_t low_fam, high_fam;
	int ret;

	if (dash) {
		*dash = '\0';
		high_ip_addr_str = dash + 1;
	}

	if (strchr(low_ip_addr_str, ':')) {
		low_fam = AF_INET6;
		*addr_sz = 16;
	} else {
		low_fam = AF_INET;
		*addr_sz = 4;
	}

	ret = inet_pton(low_fam, low_ip_addr_str, taddr);
	if (dash)
		*dash = '-';	/* put dash back so error msg is complete */
	if (ret != 1)
		return -EINVAL;

	if (high_ip_addr_str) {
		if (strchr(high_ip_addr_str, ':'))
			high_fam = AF_INET6;
		else
			high_fam = AF_INET;

		if (high_fam != low_fam)
			return -EINVAL;

		ret = inet_pton(high_fam, high_ip_addr_str, taddr_stop);

		if (ret != 1)
			return -EINVAL;
	} else
		*taddr_stop = *taddr;

	if (low_fam == AF_INET6)	/* only support IPv4 for now */
		return -EINVAL;

	return 0;
}

static int
npf_process_nat_get_filter_mask(zhashx_t *config_ht,
				const char *filter_addr_var,
				uint32_t *match_mask)
{
	char *addr = zhashx_lookup(config_ht, filter_addr_var);
	char *slash;
	char *masklen_str;
	char *endp;
	unsigned long ulong_masklen;

	if (!addr)
		return 0;

	if (addr[0] == '!')	/* no mask if negated */
		return 0;

	slash = strchr(addr, '/');

	if (!slash)
		return 0;

	masklen_str = slash + 1;

	ulong_masklen = strtoul(masklen_str, &endp, 10);
	if (endp == masklen_str || ulong_masklen > 32)
		return -EINVAL;

	*match_mask = ulong_masklen;
	return 0;
}

int
npf_process_nat_config(npf_rule_t *rl, zhashx_t *config_ht)
{
	int err;
	const char *filter_addr_var;
	uint8_t type;
	uint32_t flags = 0;
	uint8_t addr_sz = 0;
	npf_addr_t taddr;
	npf_addr_t taddr_stop;
	uint32_t match_mask = 0;
	in_port_t tport = 1;
	in_port_t tport_stop = 65535;
	uint32_t table_id = NPF_TBLID_NONE;

	memset(&taddr, 0, sizeof(taddr));
	memset(&taddr_stop, 0, sizeof(taddr_stop));

	char *value = zhashx_lookup(config_ht, "nat-type");

	if (!value)	/* not a NAT rule */
		return 0;

	if (strcmp(value, "dnat") == 0) {
		type = NPF_NATIN;
		filter_addr_var = "dst-addr";
	} else if (strcmp(value, "snat") == 0) {
		type = NPF_NATOUT;
		filter_addr_var = "src-addr";
	} else {
		RTE_LOG(ERR, FIREWALL, "NPF: unexpected value in rule: "
			"nat-type=%s\n", value);
		return -EINVAL;
	}

	bool is_exclude = false;
	value = zhashx_lookup(config_ht, "nat-exclude");
	if (value) {
		if (strcmp(value, "y") == 0) {
			is_exclude = true;
			goto end;
		} else if (strcmp(value, "n") != 0) {
			RTE_LOG(ERR, FIREWALL, "NPF: unexpected value in rule: "
				"nat-exclude=%s\n", value);
			return -EINVAL;
		}
	}

	/*
	 * Do we desire a firewall pinhole?
	 */
	value = zhashx_lookup(config_ht, "nat-pinhole");
	if (value) {
		if (strcmp(value, "y") == 0) {
			flags |= NPF_NAT_PINHOLE;
		} else if (strcmp(value, "n") != 0) {
			RTE_LOG(ERR, FIREWALL, "NPF: unexpected value in rule: "
				"nat-pinhole=%s\n", value);
			return -EINVAL;
		}
	}

	/*
	 * Handle translation ports.
	 */
	value = zhashx_lookup(config_ht, "trans-port");
	if (value) {
		err = npf_process_nat_port(&tport, &tport_stop, value);
		if (err) {
			RTE_LOG(ERR, FIREWALL, "NPF: unexpected value in rule: "
				"trans-port=%s\n", value);
			return err;
		}
	}

	/*
	 * Handle Translation addresses
	 */
	value = zhashx_lookup(config_ht, "trans-addr-masquerade");
	if (value) {
		if (strcmp(value, "y") == 0) {
			err = npf_process_nat_ip_masq(&flags, &addr_sz, &taddr,
						      &taddr_stop, rl);
			if (err)
				return err;
			goto end;
		} else if (strcmp(value, "n") != 0) {
			RTE_LOG(ERR, FIREWALL, "NPF: unexpected value in rule: "
				"trans-addr-masquerade=%s\n", value);
			return -EINVAL;
		}
	}
	value = zhashx_lookup(config_ht, "trans-addr");
	if (value) {
		err = npf_process_nat_ip_addr(&addr_sz, &taddr, &taddr_stop,
					      value);
		if (err) {
			RTE_LOG(ERR, FIREWALL, "NPF: unexpected value in rule: "
				"trans-addr=%s\n", value);
			return err;
		}
	}
	value = zhashx_lookup(config_ht, "trans-addr-group");
	if (value) {
		err = npf_addrgrp_name2tid(value, &table_id);

		if (err) {
			RTE_LOG(ERR, FIREWALL, "NPF: unknown address group in "
				"rule: trans-addr-group=%s\n", value);
			return err;
		}
		flags |= NPF_NAT_TABLE;
	}

	/*
	 * If no translation addresses configured use all addresses -
	 * 0.0.0.0-255.255.255.255
	 */
	if (addr_sz == 0 && table_id == NPF_TBLID_NONE) {
		err = npf_process_nat_ip_addr(&addr_sz, &taddr, &taddr_stop,
					      "0.0.0.0-255.255.255.255");

		if (err) {
			RTE_LOG(ERR, FIREWALL, "NPF: failed processing "
				"default translation range: "
				"0.0.0.0-255.255.255.255\n");
			return err;
		}
	}

end:
	err = npf_process_nat_get_filter_mask(config_ht, filter_addr_var,
					      &match_mask);
	if (err) {
		RTE_LOG(ERR, FIREWALL, "NPF: failed getting the mask "
			"from variable \"%s\"\n", filter_addr_var);
		return err;
	}

	/* An exclude rule is a block, and does not need a policy */
	if (is_exclude) {
		npf_rule_set_pass(rl, false);
		return 0;
	}

	err = npf_create_natpolicy(rl, type, flags, table_id, addr_sz, &taddr,
				   &taddr_stop, match_mask, tport, tport_stop);
	if (err) {
		RTE_LOG(ERR, FIREWALL, "NPF: failed to create NAT policy "
			"- error %u\n", -err);
		return err;
	}

	/* A translate rule is a pass */
	npf_rule_set_pass(rl, true);

	return 0;
}

static int
npf_handle_var(zhashx_t *config_ht, char *varvalue)
{
	char *equals = strchr(varvalue, '=');
	char *var, *value;
	char *existing_value;
	int ret;

	if (equals == NULL)
		value = strdupa("");
	else {
		*equals = '\0';
		value = equals + 1;
	}
	var = varvalue;

	existing_value = zhashx_lookup(config_ht, var);
	if (existing_value) {
		RTE_LOG(ERR, FIREWALL,
			"Duplicate setting of field \"%s\" - old value \"%s\","
			" new value \"%s\"\n", var, existing_value, value);
		return -EINVAL;
	}

	ret = zhashx_insert(config_ht, var, value);

	if (ret) {
		RTE_LOG(ERR, FIREWALL, "Out of memory setting \"%s\" to \"%s\""
			" for npf rule\n", var, value);
	}
	return ret;
}

int
npf_parse_rule_line(zhashx_t *config_ht, const char *rule_line)
{
	char *varvalue;
	/* Make a copy, as the line is edited when parsed. */
	char *rule_line_cpy = strdupa(rule_line);
	int ret;

	while ((varvalue = strsep(&rule_line_cpy, " ")) != NULL) {
		if (*varvalue == '\0')
			continue;	/* ignore multiple spaces in a row */
		ret = npf_handle_var(config_ht, varvalue);
		if (ret)
			return ret;
	}
	return 0;
}

void
npf_get_rule_match_string(zhashx_t *config_ht, char *buf, size_t *used_buf_len,
			  const size_t total_buf_len)
{
	char *addr, *port, *mac;
	char *value;
	size_t init_buf_len = *used_buf_len;

	value = zhashx_lookup(config_ht, "family");
	if (value)
		buf_app_printf(buf, used_buf_len, total_buf_len,
			       "family %s ", value);

	value = zhashx_lookup(config_ht, "proto-base");
	if (value) {
		buf_app_printf(buf, used_buf_len, total_buf_len,
			       "proto-base %s ", value);
	}

	char const *proto_key = "proto-final";
	value = zhashx_lookup(config_ht, proto_key);
	if (!value) {
		proto_key = "proto";
		value = zhashx_lookup(config_ht, proto_key);
	}
	if (value)
		buf_app_printf(buf, used_buf_len, total_buf_len,
			       "%s %s ", proto_key, value);

	value = zhashx_lookup(config_ht, "protocol-group");
	if (value)
		buf_app_printf(buf, used_buf_len, total_buf_len,
			       "protocol-group %s ", value);

	value = zhashx_lookup(config_ht, "tcp-flags");
	if (value)
		buf_app_printf(buf, used_buf_len, total_buf_len,
			       "flags %s ", value);

	value = zhashx_lookup(config_ht, "ipv6-route");
	if (value)
		buf_app_printf(buf, used_buf_len, total_buf_len,
			       "RH-type %s ", value);

	value = zhashx_lookup(config_ht, "icmpv4");
	if (!value)
		value = zhashx_lookup(config_ht, "icmpv4-group");
	if (value)
		buf_app_printf(buf, used_buf_len, total_buf_len,
			       "icmp-type %s ", value);

	value = zhashx_lookup(config_ht, "icmpv6");
	if (!value)
		value = zhashx_lookup(config_ht, "icmpv6-group");
	if (value)
		buf_app_printf(buf, used_buf_len, total_buf_len,
			       "icmp-type %s ", value);

	mac = zhashx_lookup(config_ht, "src-mac");

	addr = zhashx_lookup(config_ht, "src-addr");
	if (!addr)
		addr = zhashx_lookup(config_ht, "src-addr-group");

	port = zhashx_lookup(config_ht, "src-port");
	if (!port)
		port = zhashx_lookup(config_ht, "src-port-group");

	if (mac || addr || port)
		buf_app_printf(buf, used_buf_len, total_buf_len, "from ");

	if (mac)
		buf_app_printf(buf, used_buf_len, total_buf_len, "%s ", mac);

	if (addr || port)
		buf_app_printf(buf, used_buf_len, total_buf_len,
			       "%s ", addr ? addr : "any");
	if (port)
		buf_app_printf(buf, used_buf_len, total_buf_len,
			       "port %s ", port);

	mac = zhashx_lookup(config_ht, "dst-mac");

	addr = zhashx_lookup(config_ht, "dst-addr");
	if (!addr)
		addr = zhashx_lookup(config_ht, "dst-addr-group");

	port = zhashx_lookup(config_ht, "dst-port");
	if (!port)
		port = zhashx_lookup(config_ht, "dst-port-group");

	if (mac || addr || port)
		buf_app_printf(buf, used_buf_len, total_buf_len, "to ");

	if (mac)
		buf_app_printf(buf, used_buf_len, total_buf_len, "%s ", mac);

	if (addr || port)
		buf_app_printf(buf, used_buf_len, total_buf_len,
			       "%s ", addr ? addr : "any");

	if (port)
		buf_app_printf(buf, used_buf_len, total_buf_len,
			       "port %s ", port);

	value = zhashx_lookup(config_ht, "fragment");
	if (value)
		buf_app_printf(buf, used_buf_len, total_buf_len, "fragment ");

	value = zhashx_lookup(config_ht, "pcp");
	if (value)
		buf_app_printf(buf, used_buf_len, total_buf_len,
			       "ether class %s ", value);

	value = zhashx_lookup(config_ht, "dscp");
	if (value)
		buf_app_printf(buf, used_buf_len, total_buf_len,
			       "dscp %s ", value);

	value = zhashx_lookup(config_ht, "dscp-group");
	if (value)
		buf_app_printf(buf, used_buf_len, total_buf_len,
			       "dscp-group %s ", value);

	value = zhashx_lookup(config_ht, "ether-type");
	if (value) {
		/* convert to hex */
		char *endp;
		unsigned long type = strtoul(value, &endp, 10);

		buf_app_printf(buf, used_buf_len, total_buf_len,
			       "ether type 0x%lx ", type);
	}

	if (*used_buf_len == init_buf_len)
		/* no fields to match, so just say "all" */
		buf_app_printf(buf, used_buf_len, total_buf_len, "all ");
}

void
npf_nat_get_map_string(zhashx_t *config_ht, char *buf,
		       size_t *used_buf_len, const size_t total_buf_len)
{
	const char *value;
	const char *taddr, *tport;
	const char *pinhole;
	uint8_t type;

	value = zhashx_lookup(config_ht, "nat-type");

	if (!value)	/* not a NAT rule */
		return;

	if (strcmp(value, "dnat") == 0) {
		type = NPF_NATIN;
	} else if (strcmp(value, "snat") == 0) {
		type = NPF_NATOUT;
	} else {
		RTE_LOG(ERR, FIREWALL, "NPF: unexpected nat-type value %s\n",
			value);
		return;
	}

	value = zhashx_lookup(config_ht, "nat-exclude");
	if (value) {
		buf_app_printf(buf, used_buf_len, total_buf_len, "exclude");
		return;
	}

	pinhole = zhashx_lookup(config_ht, "nat-pinhole") ? "pinhole " : "";

	value = zhashx_lookup(config_ht, "trans-addr-masquerade");
	if (value)
		taddr = "masquerade";
	else {
		value = zhashx_lookup(config_ht, "trans-addr-group");
		if (value)
			taddr = value;
		else
			taddr = zhashx_lookup(config_ht, "trans-addr");
	}

	tport = zhashx_lookup(config_ht, "trans-port");

	if (type == NPF_NATIN) {
		buf_app_printf(buf, used_buf_len, total_buf_len,
			       "%sdynamic %s%s%s <- any",
			       pinhole,
			       taddr ? taddr : "",
			       tport ? " port " : "", tport ? tport : "");
	} else { /* type == NPF_NATOUT */
		buf_app_printf(buf, used_buf_len, total_buf_len,
			       "%sdynamic any -> %s%s%s",
			       pinhole,
			       taddr ? taddr : "",
			       tport ? " port " : "", tport ? tport : "");
	}
}
