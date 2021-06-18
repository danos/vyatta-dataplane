/*
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * A library of useful functions for writing dataplane tests.
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/sysinfo.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/mpls.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ethdev.h>

#include "main.h"
#include "controller.h"
#include "if_var.h"
#include "ip_forward.h"
#include "ip_funcs.h"
#include "in_cksum.h"
#include "rcu.h"
#include "vplane_debug.h"
#include "crypto/crypto_main.h"
#include "power.h"
#include "mpls/mpls.h"

#include "dp_test.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_netlink_state_internal.h"

static struct dp_read_pkt g_read_pkt;

static const char *
dp_test_fwd_action_str(enum dp_test_fwd_result_e fwd_action)
{
	switch (fwd_action) {
	case DP_TEST_FWD_LOCAL:
		return "received";
	case DP_TEST_FWD_DROPPED:
		return "dropped";
	case DP_TEST_FWD_CONSUMED:
		return "consumed";
	case DP_TEST_FWD_FORWARDED:
		return "forwarded";
	case DP_TEST_FWD_UNDEFINED:
		return "undefined";
	}
	dp_test_assert_internal(false);
	return "ERROR";
}

/*
 * Helper function to allow an idiom where we keep extending a string
 * into a fixed size buffer with printf style calls and keep a running
 * total of the number of non-null chars written.
 *
 * We return the number of characters in the string that results from
 * the printf unless the string with its null exactly fills the
 * remaining space at which point were return the remaining space.  So
 * subsequent calls will be given remaining == 0.
 */
int
spush(char *s, size_t remaining, const char *format, ...)
{
	int full_size;
	va_list aptr;

	va_start(aptr, format);
	full_size = vsnprintf(s, remaining, format, aptr);
	va_end(aptr);

	dp_test_assert_internal(full_size >= 0);
	if ((unsigned int)full_size + 1 < remaining)
		return  full_size;

	return remaining;
}

/*
 * Take str and remove start_trim bytes from the start and end_trim bytes from
 * the end.
 */
void
dp_test_str_trim(char *str, uint16_t start_trim, uint16_t end_trim)
{
	int i;
	int new_str_len = strlen(str) - start_trim - end_trim;

	dp_test_assert_internal(new_str_len > 0);

	for (i = 0; i < new_str_len; i++)
		str[i] = str[i + start_trim];
	str[i] = '\0';
}

static uint32_t
dp_test_ipv4_addr_mask(uint8_t len)
{
	uint32_t addr = 0xFFFFFFFF >> len;
	return ntohl(~addr);
}

/*
 * Convert an IPv4 interface address into a prefix / network address
 * In: 1.2.3.4/24
 * Out: 1.2.3.0
 *
 * NOTE: Input and output addresses are in *network* byte order
 */
uint32_t
dp_test_ipv4_addr_to_network(uint32_t addr, uint8_t prefix_len)
{
	return addr & dp_test_ipv4_addr_mask(prefix_len);
}

/*
 * Convert an IPv4 interface address into a subnet broadcast address
 * In: 1.2.3.4/24
 * Out: 1.2.3.255
 *
 * NOTE: Input and output addresses are in *network* byte order
 */
uint32_t
dp_test_ipv4_addr_to_bcast(uint32_t addr, uint8_t prefix_len)
{
	return addr | ~dp_test_ipv4_addr_mask(prefix_len);
}

/*
 * Convert an IPv6 address and prefix length to an IPv6 network address
 *
 * In: 2001:1:1::1/64
 * Out: 2001:1:1::0
 */
void
dp_test_ipv6_addr_to_network(const struct in6_addr *addr,
			     struct in6_addr *network, uint8_t prefix_len)
{
	unsigned int i;
	uint8_t mask, bits = prefix_len;

	for (i = 0; i < 16; i++) {
		if (bits >= 8) {
			mask = 0xFF;
			bits -= 8;
		} else {
			/* zero lower order (8 - bits) bits */
			mask = (0xFF >> (8 - bits)) << (8 - bits);
			bits = 0;
		}
		network->s6_addr[i] = addr->s6_addr[i] & mask;
	}
}

bool
dp_test_addr_str_to_addr(const char *addr_str, struct dp_test_addr *addr)
{
	char buf[DP_TEST_MAX_PREFIX_STRING_LEN];

	strncpy(buf, addr_str, DP_TEST_MAX_PREFIX_STRING_LEN - 1);
	buf[DP_TEST_MAX_PREFIX_STRING_LEN - 1] = '\0';

	if (inet_pton(AF_INET, buf, &addr->addr.ipv4) == 1) {
		addr->family = AF_INET;
		return true;
	}
	if (inet_pton(AF_INET6, buf, &addr->addr.ipv6) == 1) {
		addr->family = AF_INET6;
		return true;
	}

	return false;
}

const char *
dp_test_addr_to_str(const struct dp_test_addr *addr, char *addr_str,
		    size_t addr_str_size)
{
	return inet_ntop(addr->family, &addr->addr, addr_str,
			 addr_str_size);
}

bool
dp_test_prefix_str_to_prefix(const char *prefix, struct dp_test_prefix *pfx)
{
	char buf[DP_TEST_MAX_PREFIX_STRING_LEN];
	char *end = strchr(prefix, '/');
	bool ret;

	if (!end) {
		char *end;
		unsigned long label = strtoul(prefix, &end, 0);

		if (label >= 1 << 20 || *end)
			return false;

		pfx->addr.family = AF_MPLS;
		pfx->addr.addr.mpls = htonl(label << MPLS_LS_LABEL_SHIFT);
		pfx->len = 20;

		return true;
	}

	strncpy(buf, prefix, end - prefix);
	buf[end - prefix] = '\0';

	pfx->len = atoi(++end);

	ret = dp_test_addr_str_to_addr(buf, &pfx->addr);
	if (ret) {
		switch (pfx->addr.family) {
		case AF_INET:
			if (pfx->len > 32)
				return false;
			break;
		case AF_INET6:
			if (pfx->len > 128)
				return false;
			break;
		}
	}
	return ret;
}


uint8_t
dp_test_addr_size(const struct dp_test_addr *addr)
{
	switch (addr->family) {
	case AF_INET:
		return sizeof(addr->addr.ipv4);
	case AF_INET6:
		return sizeof(addr->addr.ipv6);
	case AF_MPLS:
		return sizeof(addr->addr.mpls);
	default:
		return 0;
	}
}

static char *
dp_test_parse_dp_int(const char *int_string, char **nh_int)
{
	char buf[DP_TEST_MAX_ROUTE_STRING_LEN];
	char *start = strchr(int_string, ':');
	char *end = strchrnul(int_string, ' ');

	dp_test_assert_internal(start);
	start++;
	strncpy(buf, start, end - start);
	buf[end - start] = '\0';
	*nh_int = strdup(buf);
	return end;
}

static const char *
dp_test_parse_dp_lbls(const char *lbl_string, struct dp_test_nh *nh)
{
	char buf[DP_TEST_MAX_ROUTE_STRING_LEN]; /* copy for strtok */
	uint8_t num_labels = 0;
	unsigned long label;
	char *lbl_str;
	char *end;

	strncpy(buf, lbl_string, sizeof(buf));
	buf[sizeof(buf) - 1] = '\0';

	lbl_str = strtok(buf, " ");

	if (lbl_str &&
	    strncmp(lbl_str, "nh", sizeof("nh")) == 0) {
		/* start of another nexthop - return this */
		return lbl_string;
	}
	assert(!lbl_str ||
	       (strncmp(lbl_str, "lbls", sizeof("lbls")) == 0));

	while (NULL != (lbl_str = strtok(NULL, " "))) {
		if (strcmp(lbl_str, "nh") == 0) {
			/* next nh - return a pointer to
			 * its position in the original string
			 */
			nh->num_labels = num_labels;
			return lbl_string + (lbl_str - buf);
		}
		if (strcmp(lbl_str, "imp-null") == 0) {
			label = MPLS_IMPLICITNULL;
		} else {
			label = strtoul(lbl_str, &end, 0);
			assert(end != lbl_str);
			assert(label < (1 << 20));
		}
		assert(num_labels < DP_TEST_MAX_LBLS);
		nh->labels[num_labels++] = label;
	}
	nh->num_labels = num_labels;
	/*
	 * If we get here then we have consumed the whole string
	 * return a pointer to the end of the original string.
	 */
	return lbl_string + strlen(lbl_string);
}

/*
 * Parse the given string for a NH, populating the values into the
 * given NH, and returning a ptr to where we got to in the nh_string.
 */
static const char *
dp_test_parse_dp_nh(const char *nh_string, struct dp_test_nh *nh)
{
	char buf[DP_TEST_MAX_ROUTE_STRING_LEN];
	char const *str = nh_string;

	if (!*str)
		return str;

	dp_test_assert_internal(*str == 'n');
	str++;

	dp_test_assert_internal(*str == 'h');
	str++;

	dp_test_assert_internal(*str == ' ');
	str++;

	/* Check if this is neigh_created or neigh_present */
	if (*str == 'N') {
		str++;
		if (*str == 'C') {
			str++;
			nh->neigh_created = true;
		} else if (*str == 'P') {
			str++;
			nh->neigh_present = true;
		}

		dp_test_assert_internal(*str == ' ');
		str++;

	}

	/* Looking for either an interface or an address */
	if (*str == 'i') {
		str = dp_test_parse_dp_int(str, &nh->nh_int);
	} else {
		char *end;
		int len;

		dp_test_assert_internal(!nh->neigh_created);
		end = strchrnul(str, ' ');
		len = end - str;
		strncpy(buf, str, len);
		buf[len] = '\0';
		if (!dp_test_addr_str_to_addr(buf, &nh->nh_addr))
			dp_test_abort_internal();
		str = strchrnul(str, ' ');

		if (*str) {
			/* And there may be an interface too.*/
			str++;
			if (*str == 'i')
				str = dp_test_parse_dp_int(str, &nh->nh_int);
		}

	}

	if (strncmp(str, " backup", strlen(" backup")) == 0) {
		str += strlen(" backup");
		nh->backup = true;
	}

	/*
	 * Remove any trailing whitespace
	 */
	while (*str && isspace(*str))
		str++;

	/* Be kind to callers, if empty return ->'\0' never NULL */
	dp_test_assert_internal(str);
	return str;
}

static const char *
dp_test_parse_dp_table(const char *route_string, uint32_t *tblid)
{
	const char *rstr = route_string;
	static const char *tblstr = "tbl:";
	uint32_t tid;

	if (strncmp(rstr, tblstr, strlen(tblstr)) != 0)
		tid = RT_TABLE_MAIN;
	else {
		char *e;
		long int v;
		const char *next = strchr(rstr, ' ');
		char buf[DP_TEST_MAX_ROUTE_STRING_LEN];

		rstr += strlen(tblstr);
		strncpy(buf, rstr, next - rstr);
		buf[next - rstr] = '\0';
		v = strtol(buf, &e, 10);
		dp_test_assert_internal((*e == '\0') && (v <= INT_MAX));
		tid = v;

		rstr = next;
		while (isspace(*rstr))
			rstr++;
	}

	*tblid = tid;
	return rstr;
}

static const char *
dp_test_parse_dp_vrf(const char *vrf_string, uint32_t *vrf_id)
{
	const char *vrf = vrf_string;
	const char *vrfstr = "vrf:";
	long int id = VRF_DEFAULT_ID;

	/* If no 'vrf' return VRF_DEFAULT_ID */
	if (!strncmp(vrf, vrfstr, strlen(vrfstr))) {
		/* Get the id */
		char *end;

		vrf += strlen(vrfstr);
		dp_test_assert_internal(vrf);

		id = strtol(vrf, &end, 10);
		if (id <= 0 || id >= VRF_ID_MAX)
			id = VRF_DEFAULT_ID;

		vrf = end;
		while (*vrf && isspace(*vrf))
			vrf++;
		dp_test_assert_internal(vrf);
	}

	*vrf_id = id;
	return vrf;
}

static const char *
dp_test_parse_dp_scope(const char *scope_string, uint32_t *scope)
{
	const char *scp = scope_string;
	const char *scpstr = "scope:";
	long int val = RT_SCOPE_UNIVERSE;

	/* If no 'scope' return RT_SCOPE_UNIVERSE */
	if (!strncmp(scp, scpstr, strlen(scpstr))) {
		/* Get the id */
		char *end;

		scp += strlen(scpstr);
		dp_test_assert_internal(scp);

		val = strtol(scp, &end, 10);
		if (val < RT_SCOPE_UNIVERSE || val > RT_SCOPE_NOWHERE)
			val = RT_SCOPE_UNIVERSE;

		scp = end;
		while (*scp && isspace(*scp))
			scp++;
		dp_test_assert_internal(scp);
	}

	*scope = val;
	return scp;
}

static const char *
dp_test_parse_dp_mpt(const char *mpt_string, uint32_t *payload_type)
{
	const char *mpt = mpt_string;
	const char *mptstr = "mpt:";

	*payload_type = RTMPT_IP;

	if (!strncmp(mpt, mptstr, strlen(mptstr))) {
		mpt += strlen(mptstr);
		dp_test_assert_internal(mpt);

		if (!strncmp(mpt, "ipv4", strlen("ipv4"))) {
			*payload_type = RTMPT_IPV4;
			mpt += strlen("ipv4");
		} else if (!strncmp(mpt, "ipv6", strlen("ipv6"))) {
			*payload_type = RTMPT_IPV6;
			mpt += strlen("ipv6");
		} else {
			dp_test_assert_internal(false);
		}

		while (*mpt && isspace(*mpt))
			mpt++;
	}

	return mpt;
}

static const char *
dp_test_parse_dp_prefix(const char *prefix_string,
			struct dp_test_prefix *prefix)
{
	char buf[DP_TEST_MAX_ROUTE_STRING_LEN];
	/* Find the first space */
	const char *end = strchr(prefix_string, ' ');
	int ret;

	dp_test_assert_internal(end);
	strncpy(buf, prefix_string, end - prefix_string);

	/* Prefix is now in buf. */
	buf[end - prefix_string] = '\0';
	ret = dp_test_prefix_str_to_prefix(buf, prefix);
	dp_test_assert_internal(ret);
	end++;

	/*
	 * trim whitespace - we must have at least nh after that so we can't
	 * be at the end.
	 */
	while (isspace(*end))
		end++;
	assert(*end);

	return end;
}

/*
 *  '[vrf <vrf_id>] [tbl:<tableid>] <prefix> [scope:<value>]
 *   [mpt:{ipv4|ipv6}]
 *   [blackhole|unreachable|local|
 *    {nh <addr> |nh  <addr> int:<int_name> | nh [NC|NP] int: <int_name>}
 *    [lbls {imp-null | <label>}, {imp-null | <label>} ..]]'
 *
 * '1.1.1.1/24 nh 2.2.2.2'
 * '1.1.1.1/24 nh 2.2.2.2 int:dpT1'
 * '1.1.1.1/24 nh int:dpT1'
 * '1.1.1.1/32 nh NC int:dpT1' //NC means neighbour created
 * '1.1.1.1/32 nh NP int:dpT1' //NP means neighbour present
 * 'vrf:50 1.1.1.1/24 nh 2.2.2.2 int:dpT1'
 * 'vrf:50 1.1.1.1/24 scope:0 nh 2.2.2.2 int:dpT1'
 * 'tbl:1 2.2.2.2/24 nh 3.3.3.3'
 * 'vrf:50 tbl:1 2.2.2.2/24 nh 3.3.3.3'
 *
 * '1.1.1.1/24 nh 2.2.2.2 lbls 34, 22'
 * '1.1.1.1/24 nh 2.2.2.2 int:dpT1 lbls imp-null'
 * 'vrf:50 1.1.1.1/24 nh 2.2.2.2 lbls 34, 22'
 * 'vrf:50 1.1.1.1/24 nh 2.2.2.2 int:dpT1 lbls imp-null'
 *
 * '122 nh 2.2.2.2 int:dpT1'
 * '122 nh 2.2.2.2 int:dpT1 lbls imp-null'
 * '122 nh 2.2.2.2 int:dpT1 lbls 34 42'
 */
struct dp_test_route *
dp_test_parse_route(const char *route_string)
{
	struct dp_test_route *route = calloc(sizeof(*route), 1);
	/* Populate VRF id, if present in string. Otherwise assign default */
	const char *end = dp_test_parse_dp_vrf(route_string, &route->vrf_id);

	/* Populate table id, if present in string. Otherwise assign default */
	end = dp_test_parse_dp_table(end, &route->tableid);

	/* Populate prefix */
	end = dp_test_parse_dp_prefix(end, &route->prefix);

	/* Populate scope, if present in string. Otherwise assign default */
	end = dp_test_parse_dp_scope(end, &route->scope);

	/* Get mpls payload type, if present */
	end = dp_test_parse_dp_mpt(end, &route->mpls_payload_type);

	route->type = RTN_UNICAST;

	if (route->prefix.addr.family == AF_INET ||
	    route->prefix.addr.family == AF_INET6) {
		if ((route->prefix.addr.addr.ipv6.s6_addr[0] & 0xE0) == 0xE0)
			route->type = RTN_MULTICAST;
	}

	if (!strcmp(end, "unreachable"))
		route->type = RTN_UNREACHABLE;
	else if (!strcmp(end, "blackhole"))
		route->type = RTN_BLACKHOLE;
	else if (!strcmp(end, "local"))
		route->type = RTN_LOCAL;
	else {
		/* get nexthops until we reach end of route string. */
		do {
			end = dp_test_parse_dp_nh(end,
						  &route->nh[route->nh_cnt]);
			end = dp_test_parse_dp_lbls(end,
						    &route->nh[route->nh_cnt]);
			route->nh_cnt++;
		} while (*end);
	}
	return route;
}

void dp_test_free_route(struct dp_test_route *route)
{
	unsigned int i;

	for (i = 0; i < route->nh_cnt; i++)
		free(route->nh[i].nh_int);
	free(route);
}

/*
 * Wrapper around rte_ipv4_udptcp_cksum as dataplane and rte use different
 * struct definitions.  A checksum of 0000 and FFFF are in effect the same
 * thing.   However rte_ipv4_udptcp_cksum uses FFFF whereas npf uses 0000.
 */
uint16_t
dp_test_calc_udptcp_chksum(struct rte_mbuf *m)
{
	const struct rte_ipv4_hdr *ip =
			dp_pktmbuf_mtol3(m, struct rte_ipv4_hdr *);
	const struct tcphdr *tcp = (const struct tcphdr *)(ip + 1);
	uint16_t cksum;

	cksum = rte_ipv4_udptcp_cksum(ip, (const void *)tcp);

	return cksum == 0xffff ? 0000 : cksum;
}

void
dp_test_set_tcphdr(struct rte_mbuf *m, uint16_t src_port, uint16_t dst_port)
{
	struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	struct iphdr *ip = (struct iphdr *)(eth + 1);
	struct tcphdr *tcp = (struct tcphdr *)(ip + 1);

	ip->protocol = IPPROTO_TCP;
	/* Recalc checksum */
	ip->check = 0;
	ip->check = ip_checksum(ip, ip->ihl * 4);

	tcp->source = htons(src_port);
	tcp->dest = htons(dst_port);

	tcp->check = 0;
	tcp->check = dp_test_calc_udptcp_chksum(m);
}

void
dp_test_set_iphdr(struct rte_mbuf *m, const char *src, const char *dst)
{
	struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	struct iphdr *ip = (struct iphdr *)(eth + 1);
	uint32_t addr;

	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
	ip->ihl = DP_TEST_PAK_DEFAULT_IHL;
	ip->version = 4;
	ip->tos = 0;
	ip->tot_len = htons(DP_TEST_PAK_DEFAULT_LEN);
	ip->id = 0;
	ip->frag_off = 0;
	ip->ttl = DP_TEST_PAK_DEFAULT_TTL;
	ip->protocol = DP_TEST_PAK_DEFAULT_PROTO;

	if (inet_pton(AF_INET, src, &addr) != 1)
		rte_panic("Couldn't create ip address");
	ip->saddr = addr;

	if (inet_pton(AF_INET, dst, &addr) != 1)
		rte_panic("Couldn't create ip address");
	ip->daddr = addr;

	/* Set checksum */
	ip->check = 0;
	ip->check = ip_checksum(ip, ip->ihl*4);
}

#define DP_TEST_PAK_SHOW_LINE_LEN 16

static bool
is_printable_char(char c)
{
	return (c >= 0x20 && c <= 0x7e);
}

/*
 * Record the locations of the first 'n' bytes that are different between the
 * received and expected packets.   These are then displayed in inverse video.
 */
#define DP_TEST_DIFF_AT_SIZE 50

static int
dp_test_pak_show(struct rte_mbuf *m, uint32_t start, uint32_t len,
		 const uint *diff_at, uint diff_cnt, uint diff_at_adj,
		 char *buf, uint32_t buf_len)
{
	uint i, j, written = 0;
	uint display_len;

	if (!m) {
		written += snprintf(buf + written, buf_len - written,
				    "no such packet\n            ");
		return written;
	}

	unsigned char *ptr = rte_pktmbuf_mtod(m, unsigned char *);
	ptr += start;
	unsigned int pak_len = rte_pktmbuf_pkt_len(m);

	if  (pak_len == 0) {
		written += snprintf(buf + written, buf_len - written,
				    "not enough data\n           ");
			return written;
	}

	/*
	 * space required in 'buf' is
	 *   per packet byte: 2 for the byte, 1 for space, 1 for ascii char
	 *   per line:        7 byte offset string, 2 for half-line spaces,
	 *                    plus 1 for luck
	 */
	uint nlines = pak_len / DP_TEST_PAK_SHOW_LINE_LEN + 1;
	uint space_reqd = 4*pak_len + 10*nlines;

	if  (space_reqd > (buf_len - written)) {
		written += snprintf(buf + written, buf_len - written,
				    "not enough space\n          ");
			return written;
	}

       /*
	* If the user has not specifically configured the infra to check a
	* subset of the packet then display the whole packet instead of
	* limiting the output to the length of the shortest packet in the
	* comparison.
	*/
	if (start > 0) {
		if (start + len < pak_len)
			display_len = len;
		else
			display_len = pak_len - start;
	} else {
	       display_len = pak_len;
	}

	uint inv_video_cnt = 0;
	uint ascii_idx = 0;
	char ascii[DP_TEST_PAK_SHOW_LINE_LEN + 2];
	struct rte_mbuf *m_seg = m;
	unsigned int seg_offset = 0;

	j = 0;
	for (i = 0; i < display_len; i++) {
		if (j == 0)
			written += spush(buf + written, buf_len - written,
					 "%04x   ", i);

		if (i - seg_offset == m_seg->data_len) {
			seg_offset = i;
			m_seg = m_seg->next;
			ptr = rte_pktmbuf_mtod(m_seg, unsigned char *);
		}

		if (inv_video_cnt < diff_cnt &&
		    diff_at[inv_video_cnt] == i + diff_at_adj) {
			/* Inverse video */
			written += spush(buf + written, buf_len - written,
					 TEXT_INVERSE "%02x" TEXT_RESET,
					 (uint)*ptr);
			inv_video_cnt++;
		} else
			written += spush(buf + written, buf_len - written,
					 "%02x", (uint)*ptr);

		written += spush(buf + written, buf_len - written, " ");

		ascii[ascii_idx++] = is_printable_char(*ptr) ? *ptr : '.';

		ptr++;
		j++;

		/* Add a space half-way along line */
		if (j == DP_TEST_PAK_SHOW_LINE_LEN / 2) {
			written += spush(buf + written, buf_len - written, " ");
			ascii[ascii_idx++] = ' ';
		}

		if (j == DP_TEST_PAK_SHOW_LINE_LEN) {
			ascii[ascii_idx] = '\0';
			ascii_idx = 0;

			j = 0;
			written += spush(buf + written,
					 buf_len - written,
					 " %s\n", ascii);
		}
	}

	/*
	 * Pad line with spaces so that last ascii string lines up
	 */
	if (j < DP_TEST_PAK_SHOW_LINE_LEN) {
		uint nspaces;

		nspaces = (DP_TEST_PAK_SHOW_LINE_LEN - j) * 3;
		if (j < DP_TEST_PAK_SHOW_LINE_LEN / 2)
			nspaces++;

		written += spush(buf + written, buf_len - written,
				 "%*c", nspaces, ' ');
	}

	ascii[ascii_idx] = '\0';
	written += spush(buf + written, buf_len - written,
			 " %s\n", ascii);
	return written;
}

static unsigned int
dp_test_build_sent_string(char *buf, uint32_t buf_len, struct rte_mbuf *m,
			  uint32_t len, uint *diff_at, uint diff_cnt,
			  uint diff_at_adj)
{
	unsigned int written = 0;

	if (!buf)
		return 0;

	written += spush(buf, buf_len, "sent    :\n");
	written += dp_test_pak_show(m,
				    0, /* always show from l2 start */
				    len, diff_at, diff_cnt, diff_at_adj,
				    buf + written,
				    buf_len - written);
	return written;
}

static unsigned int
dp_test_build_exp_string(char *buf, uint32_t buf_len, struct rte_mbuf *m,
			 uint32_t len, uint *diff_at, uint diff_cnt,
			 const char *pak_info)
{
	unsigned int written = 0;

	written += spush(buf, buf_len, "expected%s:\n", pak_info);
	written += dp_test_pak_show(m,
				    0, /* always show from l2 start */
				    len, diff_at, diff_cnt, 0,
				    buf + written,
				    buf_len - written);
	return written;
}

static unsigned int
dp_test_build_rcv_string(char *buf, uint32_t buf_len, struct rte_mbuf *m,
			 uint32_t len, uint *diff_at, uint diff_cnt,
			 const char *pak_info)
{
	unsigned int written = 0;

	written += spush(buf, buf_len, "received%s:\n", pak_info);
	written += dp_test_pak_show(m,
				    0, /* always show from l2 start */
				    len, diff_at, diff_cnt, 0,
				    buf + written,
				    buf_len - written);
	return written;
}

/*
 * Max Packet size, displayed as sent and exp,
 * with 3 bytes to display each byte.
 */
#define DP_TEST_BUF_DISPLAY_SIZE (9000 * 2 * 3)
void
dp_test_pak_verify(struct rte_mbuf *m, struct ifnet *ifp,
		   struct dp_test_expected *expected,
		   enum dp_test_fwd_result_e fwd_result)
{
	uint i;
	unsigned char *exp, *rcv;
	unsigned int written = 0;
	static char buf[DP_TEST_BUF_DISPLAY_SIZE];
	unsigned int check;
	uint32_t check_len;
	uint32_t check_start;
	uint32_t sent_check_len;
	uint32_t total_len;
	struct rte_mbuf *m_temp;
	uint16_t vlan_tci;

	const char *file = expected->file;
	int line = expected->line;

	/*
	 * Record offsets of the first 'n' different bytes
	 */
	int different = 0;	/* Number of different bytes */
	int different_at = 0;	/* Offset of first different byte */
	uint diff_at[DP_TEST_DIFF_AT_SIZE];

	/* Step over any packets we expect to have been dropped or consumed */
	do {
		check = expected->last_checked;
		expected->last_checked++;
	} while (check < expected->exp_num_paks &&
			(expected->fwd_result[check] == DP_TEST_FWD_DROPPED ||
			 expected->fwd_result[check] == DP_TEST_FWD_CONSUMED));

	/* Use local copy of check_start, check_len */
	if (check < expected->exp_num_paks) {
		check_start = expected->check_start[check];
		check_len = expected->check_len[check];
	} else {
		/*
		 * Received more packets than we expected so no
		 * information on where to start checking from and the
		 * length is available.
		 */
		check_start = 0;
		check_len = 0;
	}
	sent_check_len = check_len;

	if (check >= expected->exp_num_paks) {
		int8_t dropped = 0;

		/* Count the paks we expect to have dropped before this one */
		for (i = 0; i < check; i++)
			if (expected->fwd_result[i] == DP_TEST_FWD_DROPPED ||
			    expected->fwd_result[i] == DP_TEST_FWD_CONSUMED)
				dropped++;

		written = 0;

		/*
		 * Since we don't know which sent packet caused the
		 * extra received packet, display the last sent packet
		 * which is the most likely candidate.
		 */
		written += dp_test_build_sent_string(
			buf + written,
			sizeof(buf) - written,
			dp_test_exp_get_sent(expected,
					     expected->exp_num_paks - 1),
			sent_check_len + check_start,
			NULL, 0, 0);

		written += spush(buf + written,
				 sizeof(buf) - written,
				 "received:\n");
		written +=
			dp_test_pak_show(m, check_start, check_len,
					 NULL, 0, 0,
					 buf + written,
					 sizeof(buf) - written);
		_dp_test_fail(file, line,
			      "(%d) expected %"PRIu32" packets, but got %"PRIu32" packets"
			      "\n%s\n%s",
			      check - dropped, expected->exp_num_paks - dropped,
			      check + 1 - dropped,
			      expected->description, buf);
	}

	written += dp_test_build_sent_string(
		buf + written,
		sizeof(buf) - written,
		dp_test_exp_get_sent(expected, check),
		sent_check_len + check_start,
		NULL, 0, 0);

	(void) written;

	if (fwd_result != expected->fwd_result[check]) {
		bool final_result = false;  /* VR failure */

		_dp_test_fail_unless(final_result,
				     file, line,
				     "(%d) packet was %s but expected it to be %s\n%s\n%s",
				     check, dp_test_fwd_action_str(fwd_result),
				     dp_test_fwd_action_str(
						expected->fwd_result[check]),
				     expected->description, buf);
	}

	if (!expected->cloned)
		/* Is this the same mbuf we sent ? */
		if (expected->compare_pak_addr)
			_dp_test_fail_unless(
				expected->pak_addr[check] == (intptr_t)m,
				file, line,
				"\n(%d) expected->pak_addr(0x%"PRIXPTR") != m (0x%"PRIXPTR")",
				check, expected->pak_addr[check], (intptr_t)m);

	/* Check the output interface only if the packet was forwarded */
	if (expected->fwd_result[check] == DP_TEST_FWD_FORWARDED)
		_dp_test_fail_unless((strncmp(ifp->if_name,
					     expected->oif_name[check],
					     IFNAMSIZ) == 0),
				     file, line,
				     "\n(%d) ifp->if_name (%s) != expected->oif_name (%s)"
				     "\n%s\n%s",
				     check, ifp->if_name,
				     expected->oif_name[check],
				     expected->description, buf);
	/* Check the vlan is correct */
	if (expected->fwd_result[check] == DP_TEST_FWD_FORWARDED &&
	    m->ol_flags & PKT_TX_VLAN_PKT)
		vlan_tci = m->vlan_tci;
	else if (expected->fwd_result[check] == DP_TEST_FWD_LOCAL &&
		 m->ol_flags & PKT_RX_VLAN)
		vlan_tci = m->vlan_tci;
	else
		vlan_tci = 0;
	_dp_test_fail_unless(
		vlan_tci == expected->exp_pak[check]->vlan_tci,
		file, line,
		"\n(%d) m->vlan_tci (%u) != expected->vlan_tci (%u)\n%s\n%s",
		check, vlan_tci, expected->exp_pak[check]->vlan_tci,
		expected->description, buf);

	/* Verify that the mbuf length(s) are self consistent */
	total_len = 0;
	m_temp = m;
	while (m_temp) {
		total_len += m_temp->data_len;
		m_temp = m_temp->next;
	}
	_dp_test_fail_unless(
		m->pkt_len == total_len,
		file, line,
		"(%d) mbuf length not self consistent: pkt_len %d, data_len_sum %d",
		check, m->pkt_len, total_len);

	/* Verify that the mbuf L2 length is valid for Ethernet frames */
	_dp_test_fail_unless(
		m->l2_len >= RTE_ETHER_HDR_LEN, file, line,
		"(%d) Invalid mbuf L2 length for Ethernet pkt: %d",
		check, m->l2_len);

	/* Verify the data in the mbuf */
	exp = rte_pktmbuf_mtod(expected->exp_pak[check], unsigned char *);
	rcv = rte_pktmbuf_mtod(m, unsigned char *);

	exp += check_start;
	rcv += check_start;

	if (rte_pktmbuf_pkt_len(expected->exp_pak[check]) < check_len)
		check_len = rte_pktmbuf_pkt_len(expected->exp_pak[check]);

	uint diff_cnt = 0;
	struct rte_mbuf *exp_seg = expected->exp_pak[check];
	struct rte_mbuf *rcv_seg = m;
	unsigned int exp_seg_offset = check_start;
	unsigned int rcv_seg_offset = check_start;
	bool short_rcv = false;

	for (i = 0; i < check_len; i++) {
		while (i - exp_seg_offset == exp_seg->data_len) {
			exp_seg_offset = i;
			exp_seg = exp_seg->next;
			exp = rte_pktmbuf_mtod(exp_seg, unsigned char *);
		}

		while (!short_rcv &&
		       (i - rcv_seg_offset == rcv_seg->data_len)) {
			rcv_seg_offset = i;
			rcv_seg = rcv_seg->next;
			if (!rcv_seg)
				short_rcv = true;
			else
				rcv = rte_pktmbuf_mtod(rcv_seg, void *);
		}

		if (short_rcv || (*exp != *rcv)) {
			if (dp_test_exp_care(expected, check, i)) {
				if (different == 0)
					different_at = i;
				different++;
				if (diff_cnt < DP_TEST_DIFF_AT_SIZE)
					diff_at[diff_cnt++] = i + check_start;
				if (short_rcv)
					break;
			}
		}
		exp++;
		rcv++;
	}

	if (different) {
		char pak_info[40];
		uint diff_at_adj = 0;
		struct rte_mbuf *sent_pak;

		sent_pak = dp_test_exp_get_sent(expected, check);

		spush(pak_info, sizeof(pak_info),
		      " (%d) check_start %d check_len %d", check,
		      check_start, check_len);
		written = 0;

		if (strlen(expected->description))
			written += spush(buf + written,
					 sizeof(buf) - written,
					 "\n%s",
					 expected->description);

		/*
		 * 'different_at' is the offset of the first different byte
		 * relative to the start of the *sent* packet.
		 */
		written += spush(buf + written,
				 sizeof(buf) - written,
				 "\n%s: TEST FAILED: %s: %u bytes different "
				 "starting at byte %d:\n",
				 dp_test_pname, expected->func,
				 different, different_at);

		written += dp_test_build_sent_string(
			buf + written,
			sizeof(buf) - written,
			sent_pak,
			sent_check_len + check_start,
			diff_at, diff_cnt, diff_at_adj);

		written += dp_test_build_exp_string(
			buf + written,
			sizeof(buf) - written,
			expected->exp_pak[check],
			sent_check_len + check_start,
			diff_at, diff_cnt,
			pak_info);

		written += dp_test_build_rcv_string(
			buf + written,
			sizeof(buf) - written,
			m,
			sent_check_len + check_start,
			diff_at, diff_cnt,
			pak_info);

		(void) written;

		_dp_test_fail(file, line, "%s", buf);
	} else {
		expected->pak_correct[check] = true;
	}

	/* Record the fact the packet made it to the expected end */
	expected->pak_checked[check] = true;
}

/*
 * Given the test interface name of form dpxTy find the ring that is
 * used to inject packets.
 */
static struct rte_ring *
dp_test_intf_name2ring(const char *if_name, const char *base)
{
	char name[IFNAMSIZ] = {0};

	snprintf(name, IFNAMSIZ, "%s", base);

	/* Interface name can be in either format dpxTy, or dpTxy */
	if (if_name[3] == 'T')
		name[7] = if_name[2];
	else
		name[7] = if_name[3];

	name[8] = if_name[4];

	return rte_ring_lookup(name);
}

static struct rte_ring *
dp_test_intf_name2rx_ring(const char *real_name)
{
	return dp_test_intf_name2ring(real_name, DP_TEST_RX_RING_BASE_NAME);
}

static struct rte_ring *
dp_test_intf_name2tx_ring(const char *if_name)
{
	return dp_test_intf_name2ring(if_name, DP_TEST_TX_RING_BASE_NAME);
}

int dp_test_pak_get_from_ring(const char *if_name,
			      struct rte_mbuf **bufs,
			      int count)
{
	struct rte_ring *ring;

	ring = dp_test_intf_name2tx_ring(if_name);
	count = rte_ring_mc_dequeue_burst(ring,
					  (void **)bufs,
					  count,
					  NULL);
	return count;
}

/*
 * Loop over all the tx rings checking for packets. For any that are
 * received, run the verify cb and then free the mbuf.
 * If wait_for_first flag is set, then allow up to 1s for the first
 * packet to appear before timing out.
 */
static void dp_test_verify_tx(bool wait_for_first)
{
	int i, j, count;
	struct ifnet *ifp;
	struct rte_mbuf *bufs[64];
	int timeout = USEC_PER_SEC;

	while (1) {
		for (i = 0; i < dp_test_intf_count_local(); i++) {
			ifp = ifnet_byport(i);
			count = dp_test_pak_get_from_ring(
				ifp->if_name,
				(struct rte_mbuf **)&bufs,
				64);
			if (count) {
				for (j = 0; j < count; j++) {
					dp_test_assert_internal(
							bufs[j] != NULL);
					(*dp_test_exp_get_validate_cb(
					    dp_test_global_expected))
					    (bufs[j], ifp,
					     dp_test_global_expected,
					     DP_TEST_FWD_FORWARDED);
					rte_pktmbuf_free(bufs[j]);
				}
				wait_for_first = false;
			}
		}

		if (!wait_for_first || --timeout == 0)
			break;

		usleep(1);
	}
}

static void
dp_test_wait_until_tx_processed(void)
{
	/*
	 * Ensure all packets have been dequeued from
	 * the TX ring and processed.
	 */
	dp_rcu_synchronize();
	/*
	 * Ensure that if portmonitoring is enabled
	 * that all packets have been dequeued from
	 * the second TX ring and processed.
	 */
	dp_rcu_synchronize();
	/*
	 * Just in case QOS has been configured and is
	 * using a transmit thread.
	 */
	dp_rcu_synchronize();
}

/*
 * Wait for all interfaces to process any packets that have been sent.
 *
 * This assumes that if we have emptied the RX ring and reached the
 * quiescent state thrice then there are no packets in flight. This
 * depends on the following assumptions:
 * 1. We have only one forwarding thread doing RX, crypto and TX, so
 *    there can be no packets queued between forwarding threads.
 * 2. That crypto cannot generate work for RX, and that TX cannot
 *    generate work for RX or crypto.
 * 3. That the number of packets dequeued by crypto & TX each time
 *    around is either >= that for RX, or is >= the max supported number
 *    of packets injected by the test infra.
 */
void dp_test_intf_wait_until_processed(struct rte_ring *ring)
{

	unsigned int i;

	/* loop until the counters are incremented by count, or timeout */
	for (i = 0; i < USEC_PER_SEC; i++) {
		if (rte_ring_empty(ring)) {
			/*
			 * Ensure all packets have made it from an RX
			 * thread to a TX ring, having drained the pkt-burst.
			 */
			dp_rcu_synchronize();
			dp_test_wait_until_tx_processed();
			return;
		}
		usleep(1);
	}
	dp_test_fail("RX ring not emptied");
}

static void
dp_test_wait_until_local_processed(struct dp_test_expected *expected,
		uint32_t num_paks, uint32_t local_paks)
{
	uint32_t i, j;

	for (i = 0; i < USEC_PER_SEC; i++) {
		uint32_t found = 0;

		for (j = 0; j < num_paks; j++) {
			if (expected->fwd_result[j] == DP_TEST_FWD_LOCAL
					&& expected->pak_checked[j] == true)
				found++;
		}
		if (found == local_paks)
			return;
		usleep(1);
	}
}

void dp_test_pak_add_to_ring(const char *iif_name,
			     struct rte_mbuf **paks_to_send,
			     uint32_t num_paks,
			     bool wait_until_processed)
{
	struct rte_ring *ring;

	ring = dp_test_intf_name2rx_ring(iif_name);
	dp_test_assert_internal(ring);
	/*
	 * Enqueue onto the ring, which will then be picked up
	 * by the driver at the next poll.
	 */
	rte_ring_mp_enqueue_burst(ring, (void **)paks_to_send, num_paks, NULL);

	if (wait_until_processed)
		dp_test_intf_wait_until_processed(ring);
}

/*
 * Global expected pak that the wrapped end of the processing path can access
 * so that it can verify the contents.
 */
struct dp_test_expected *dp_test_global_expected;

void
dp_test_pak_inject(struct rte_mbuf **paks_to_send, uint32_t num_paks,
		   const char *iif_name, struct dp_test_expected *expected,
		   const char *test_type)
{
	uint32_t i;
	uint32_t local_paks = 0;

	for (i = 0; i < num_paks; i++) {
		/* usually, DPDK would do this for us */
		paks_to_send[i]->port = dp_test_intf_name2port(iif_name);

		/* Copy what we are about to send */
		expected->sent_pak[i] = dp_test_cp_pak(paks_to_send[i]);

		/* Record address of rx pak buf, check it is same one on tx */
		expected->pak_addr[i] = (intptr_t)paks_to_send[i];
		if (expected->fwd_result[i] == DP_TEST_FWD_LOCAL)
			local_paks++;
	}

	if (dp_debug == ~0ul)
		printf("\n%s: %s START %s:%d\n", dp_test_pname, test_type,
		       expected->file, expected->line);

	/*
	 * Copy the mbufs into the ring for the interface.
	 */
	dp_test_pak_add_to_ring(iif_name, paks_to_send, num_paks, true);
	if (local_paks)
		dp_test_wait_until_local_processed(expected, num_paks,
				local_paks);
	dp_test_verify_tx(false);

	if (dp_debug == ~0ul) {
		bool pass, overall_pass;
		unsigned int i;

		overall_pass = true;
		printf("%s: %s END %s:%d", dp_test_pname, test_type,
		       expected->file, expected->line);
		for (i = 0; i < expected->exp_num_paks; i++) {
			pass = expected->pak_correct[i] ||
				(!expected->pak_checked[i] &&
				 (expected->fwd_result[i] ==
				  DP_TEST_FWD_DROPPED ||
				  expected->fwd_result[i] ==
				  DP_TEST_FWD_CONSUMED));
			printf(
			       "[pak %u: checked %s, correct %s, action %s, pak %s]",
			       i, expected->pak_checked[i] ? "Y" : "N",
			       expected->pak_correct[i] ? "Y" : "N",
			       dp_test_fwd_action_str(expected->fwd_result[i]),
			       pass ? "PASS" : "FAIL");
			if (!pass)
				overall_pass = false;
		}
		printf(" result %s\n\n", overall_pass ? "GOOD" : "BAD");
	}
}

void
_dp_test_pak_rx_for(struct rte_mbuf *pak, const char *if_name,
		    struct dp_test_expected *exp,
		    const char *file, const char *func, int line,
		    const char *fmt_str, ...)
{
	va_list ap;

	va_start(ap, fmt_str);
	vsnprintf(exp->description, sizeof(exp->description),
		  fmt_str, ap);
	_dp_test_pak_receive(pak, if_name, exp, file, func, line);
	va_end(ap);
}

static bool
dp_test_pak_check_fwd_result(struct dp_test_expected *expected,
			     const char *file, int line)
{
	unsigned int i;
	unsigned int written = 0;
	char buf[DP_TEST_BUF_DISPLAY_SIZE];
	bool result = true;

	/* Did we get all the packets we expected */
	for (i = 0; i < expected->exp_num_paks; i++) {
		if (!expected->pak_checked[i] &&
		    (expected->fwd_result[i] != DP_TEST_FWD_DROPPED &&
		     expected->fwd_result[i] != DP_TEST_FWD_CONSUMED)) {
			result = false;
			break;
		}
	}

	if (result == false) {
		char pak_info[40];

		spush(pak_info, sizeof(pak_info),
			" (%d) check_start %d check_len %d", 0,
			expected->check_start[i], expected->check_len[i]);

		written += dp_test_build_sent_string(buf + written,
					sizeof(buf) - written,
					dp_test_exp_get_sent(expected, i),
					expected->check_start[i] +
					expected->check_len[i],
						     NULL, 0, 0);

		written += dp_test_build_exp_string(buf + written,
						    sizeof(buf) - written,
						    expected->exp_pak[i],
						    expected->check_start[i] +
						    expected->check_len[i],
						    NULL, 0, pak_info);

		if (expected->fwd_result[i] == DP_TEST_FWD_FORWARDED)
			written += spush(buf + written,
					 sizeof(buf) - written,
					 "to be forwarded onto: %s",
					 expected->oif_name[i]);

		(void) written;

		_dp_test_fail(file, line, "%s\nMissing packet:\n%s",
			      expected->description, buf);
	}
	return result;
}

static void dp_test_set_expected(struct dp_test_expected *expected,
		const char *file, const char *func, int line)
{
	unsigned int i;

	for (i = 0; i < DP_TEST_MAX_EXPECTED_PAKS; i++) {
		if (expected->fwd_result[i] == DP_TEST_FWD_FORWARDED) {
			dp_test_assert_internal(expected->oif_name[i]);
			expected->oif_name[i] =
				dp_test_intf_real(expected->oif_name[i],
						  expected->real_oif_name[i]);
		}
		expected->pak_checked[i] = false;
		expected->pak_correct[i] = false;
	}

	expected->file = file;
	expected->func = func;
	expected->line = line;
	dp_test_global_expected = expected;
	expected->last_checked = 0;
}

void
_dp_test_pak_receive_n(struct rte_mbuf **paks, uint32_t num_paks,
		       const char *if_name,
		       struct dp_test_expected *expected,
		       const char *file, const char *func, int line)
{
	bool overall_result = true;

	dp_test_assert_internal(paks);
	dp_test_assert_internal(if_name);
	dp_test_assert_internal(expected);
	dp_test_assert_internal(num_paks <= DP_TEST_MAX_EXPECTED_PAKS);
	dp_test_assert_internal(expected->exp_num_paks <=
				DP_TEST_MAX_EXPECTED_PAKS);

	dp_test_set_expected(expected, file, func, line);

	if ((dp_test_intf_type(if_name) ==
	     DP_TEST_INTF_TYPE_SWITCH_PORT) &&
	    !dp_test_intf_switch_port_over_bkp(if_name)) {
		uint32_t device, port, dpid;
		struct rte_ring *ring;
		char ring_name[32];

		/*
		 * A wait is required to allow for the packet to be
		 * transferred from the RX queue to local Tx burst queue
		 * and to the actual output queue.
		 */
		if (sscanf(if_name, "dp%usw_port_%u_%u", &dpid, &device,
			   &port) != 3)
			dp_test_assert_internal(false);
		snprintf(ring_name, 32, "net_sw_portsw%uport%u-rx-0",
			 device, port);
		ring = rte_ring_lookup(ring_name);
		dp_test_intf_wait_until_processed(ring);

		dp_test_verify_tx(false);
		goto verify_result;
	}

	dp_test_pak_inject(paks, num_paks, if_name, expected, "VR");

verify_result:
	overall_result = dp_test_pak_check_fwd_result(expected, file,
						      line);

	ck_assert(overall_result);
	dp_test_exp_delete(expected);
}

void
_dp_test_pak_receive(struct rte_mbuf *pak, const char *if_name,
		     struct dp_test_expected *expected,
		     const char *file, const char *func, int line)
{
	_dp_test_pak_receive_n(&pak, 1, if_name, expected, file,
			       func, line);
}

void _dp_test_pak_tx_without_rx(struct dp_test_expected *expected,
				const char *file, const char *func, int line)
{
	bool overall_result = true;

	dp_test_assert_internal(expected);
	dp_test_assert_internal(expected->exp_num_paks <=
				DP_TEST_MAX_EXPECTED_PAKS);

	dp_test_set_expected(expected, file, func, line);
	dp_test_verify_tx(true);
	overall_result = dp_test_pak_check_fwd_result(expected, file,
						      line);

	ck_assert(overall_result);
	dp_test_exp_delete(expected);
}

void dp_test_exp_validate_cb_pak_done(struct dp_test_expected *exp,
				      bool correct)
{
	exp->pak_correct[exp->last_checked] = correct;
	exp->pak_checked[exp->last_checked] = true;
	exp->last_checked++;
}

static uint64_t dp_test_get_shadow_tx_stat(portid_t port_id)
{
	struct shadow_if_info *sii = get_port2shadowif(port_id);

	if (!sii)
		return 0;
	return sii->ts_packets;
}

/* wait until the packet is counted for by the processing thread.
 * Note: This does not check if the packet is consumed/forwarded successfully
 */
static void dp_test_shadow_intf_wait_until_processed(uint64_t old_count,
		portid_t portid, uint32_t num_pkts, const char *file, int line)
{
	uint32_t i;

	/* Waiting for at the most 2 secs for the packet to be picked up by the
	 * receiving thread
	 */
	for (i = 0; i < 2*USEC_PER_SEC; i++) {
		usleep(1);
		uint64_t new_count = dp_test_get_shadow_tx_stat(portid);

		if (new_count - old_count >= num_pkts) {
			dp_test_wait_until_tx_processed();
			return;
		}
	}
	_dp_test_fail(file, line,
			"Shadow Interface tx counter not incremented");
}

void _dp_test_send_slowpath_pkt(struct rte_mbuf *pak,
		struct dp_test_expected *expected,
		const char *file, const char *func, int line)
{
	char real_ifname[IFNAMSIZ];
	bool overall_result = true;

	/* VR uplink slowpath */
	dp_test_assert_internal(pak);
	dp_test_assert_internal(expected);
	dp_test_assert_internal(expected->oif_name[0]);

	dp_test_set_expected(expected, file, func, line);

	/* Find port id of the output interface */
	dp_test_intf_real(expected->oif_name[0], real_ifname);

	portid_t portid = dp_test_intf_name2port(real_ifname);
	uint64_t old_count = dp_test_get_shadow_tx_stat(portid);

	/* Copy what we are about to send */
	expected->sent_pak[0] = dp_test_cp_pak(pak);
	/* Inject packet into slowpath */
	dp_test_inject_pkt_slow_path(pak, portid, 0, 0, 0);

	/* Trigger slowpath packet processing */
	if (dp_debug == ~0ul)
		printf("\n%s: VR(slow) START %s:%d (port %u)\n",
		       dp_test_pname,
		       expected->file, expected->line,
		       portid);
	write(shadow_pipefd[portid], "p", 1);

	/* Verify the packet processing  */
	dp_test_shadow_intf_wait_until_processed(old_count, portid, 1,
			file, line);
	if (dp_debug == ~0ul)
		printf("%s: VR(slow) END %s:%d\n", dp_test_pname,
		       expected->file, expected->line);
	dp_test_verify_tx(false);
	overall_result = dp_test_pak_check_fwd_result(expected, file, line);

	ck_assert(overall_result);
	dp_test_exp_delete(expected);
}

void dp_test_inject_pkt_slow_path(struct rte_mbuf *pkt, portid_t port,
				  uint32_t ifindex, uint16_t flags,
				  uint16_t proto)
{
	g_read_pkt.pkt = pkt;
	g_read_pkt.port = port;
	g_read_pkt.m.flags = flags;
	g_read_pkt.m.ifindex = ifindex;
	g_read_pkt.p.proto = htons(proto);
}

/*
 * Inject a packet into the dataplane .spathintf
 */
void
_dp_test_send_spath_pkt(struct rte_mbuf *pak, const char *virt_oif_name,
		   struct dp_test_expected *exp, const char *file,
		   const char *func, int line)
{
	bool overall_result = true;
	char real_ifname[IFNAMSIZ];
	uint64_t old_count;
	struct shadow_if_info *sii;

	sii = get_fd2shadowif(spath_pipefd[0]);

	dp_test_assert_internal(pak);
	dp_test_assert_internal(exp);
	dp_test_assert_internal(sii);
	dp_test_assert_internal(virt_oif_name);

	dp_test_set_expected(exp, file, func, line);

	/* Copy what we are about to send */
	exp->sent_pak[0] = dp_test_cp_pak(pak);

	/* Record address of rx pak buf so we can check it is same one on tx */
	exp->pak_addr[0] = (intptr_t)pak;

	/* Find index of the output interface */
	dp_test_intf_real(virt_oif_name, real_ifname);
	int ifindex = dp_test_intf_name2index(real_ifname);

	/* For .spath interface the ifp pointed by the meta.iif has changes in
	 * statistics. Hence to check if the packet is picked up for processing,
	 * checking the out packet count.
	 */
	portid_t portid = sii->port;

	old_count = dp_test_get_shadow_tx_stat(portid);

	/* Inject packet into slowpath */
	dp_test_inject_pkt_slow_path(pak, 0, ifindex, TUN_META_FLAG_IIF,
			ETH_P_TEB);

	/* Trigger the reader */
	write(spath_pipefd[1], "p", 1);

	dp_test_shadow_intf_wait_until_processed(old_count, portid, 1,
			file, line);
	dp_test_verify_tx(false);

	overall_result = dp_test_pak_check_fwd_result(exp, file, line);

	ck_assert(overall_result);
	dp_test_exp_delete(exp);
}

struct rte_mbuf *dp_test_get_read_pkt(void)
{
	struct rte_mbuf *m = g_read_pkt.pkt;

	g_read_pkt.pkt = NULL;
	return m;
}

uint16_t dp_test_get_read_meta_flags(void)
{
	uint16_t flags = g_read_pkt.m.flags;

	g_read_pkt.m.flags = 0;
	return flags;
}

uint32_t dp_test_get_read_meta_iif(void)
{
	uint32_t id = g_read_pkt.m.ifindex;

	g_read_pkt.m.ifindex = 0;
	return id;
}

uint16_t dp_test_get_read_proto(void)
{
	uint16_t proto = g_read_pkt.p.proto;

	g_read_pkt.p.proto = 0;
	return proto;
}

bool dp_test_read_pkt_available(void)
{
	return g_read_pkt.pkt != NULL;
}

void dp_test_enable_soft_tick_override(void)
{
	enable_soft_clock_override();
}

void dp_test_disable_soft_tick_override(void)
{
	disable_soft_clock_override();
}

#define DP_TEST_MAX_UNUSABLE 100
static struct dp_rt_path_unusable_key dp_test_unusable[DP_TEST_MAX_UNUSABLE];
static int dp_test_current_unusable;

static bool dp_test_paths_equal(const struct dp_rt_path_unusable_key *key1,
				const struct dp_rt_path_unusable_key *key2)
{
	if (key1->type == key2->type &&
	    key1->ifindex == key2->ifindex) {

		if (key1->type == DP_RT_PATH_UNUSABLE_KEY_INTF_NEXTHOP) {
			if (dp_addr_eq(&key1->nexthop,
				       &key2->nexthop))
				return true;
		} else {
			return true;
		}
	}
	return false;
}

static enum dp_rt_path_state
dp_test_get_path_usable(const struct dp_rt_path_unusable_key *key)
{
	int i;

	for (i = 0; i < dp_test_current_unusable; i++) {
		if (dp_test_paths_equal(key, &dp_test_unusable[i]))
			return DP_RT_PATH_UNUSABLE;
	}

	return DP_RT_PATH_UNKNOWN;
}

void dp_test_clear_path_unusable(void)
{
	dp_test_current_unusable = 0;
}

static void dp_test_set_nh_state(const char *interface,
				 const char *nexthop,
				 bool usable)
{
	static int registered_usable_cb;
	struct dp_test_addr addr;
	struct dp_rt_path_unusable_key key;
	enum dp_rt_path_state state;

	if (usable)
		state = DP_RT_PATH_USABLE;
	else
		state = DP_RT_PATH_UNUSABLE;

	if (!registered_usable_cb) {
		dp_rt_register_path_state("test_infra",
					  dp_test_get_path_usable);
		registered_usable_cb = true;
	}
	dp_test_assert_internal(dp_test_current_unusable <
				DP_TEST_MAX_UNUSABLE);

	/* nexthop is allowed to be null */
	if (nexthop) {
		if (!dp_test_addr_str_to_addr(nexthop, &addr))
			dp_test_assert_internal(false);

		dp_test_assert_internal(addr.family == AF_INET ||
					addr.family == AF_INET6);

		key.type = DP_RT_PATH_UNUSABLE_KEY_INTF_NEXTHOP;
		key.nexthop.type = addr.family;
		memcpy(&key.nexthop.address, &addr.addr,
		       sizeof(key.nexthop.address));
	} else {
		key.type = DP_RT_PATH_UNUSABLE_KEY_INTF;
	}

	key.ifindex = dp_test_intf_name2index(interface);

	/* Store for later use */
	dp_test_unusable[dp_test_current_unusable] = key;
	dp_test_current_unusable++;

	dp_rt_signal_path_state("tests", state, &key);
}

void dp_test_make_nh_unusable(const char *interface,
			      const char *nexthop)
{
	dp_test_set_nh_state(interface, nexthop, false);
}

void dp_test_make_nh_usable(const char *interface,
			    const char *nexthop)
{
	dp_test_set_nh_state(interface, nexthop, true);
}


static void nh_set_state(struct dp_rt_path_unusable_key *key,
			 enum dp_rt_path_state state)
{
	dp_rcu_register_thread();
	dp_rcu_thread_online();

	dp_rt_signal_path_state("tests", state, key);

	dp_rcu_thread_offline();
	dp_rcu_unregister_thread();
}

static void *nh_unusable(void *arg)
{
	struct dp_rt_path_unusable_key *key = arg;

	nh_set_state(key, DP_RT_PATH_UNUSABLE);
	free(key);
	return 0;
}

static void *nh_usable(void *arg)
{
	struct dp_rt_path_unusable_key *key = arg;

	nh_set_state(key, DP_RT_PATH_USABLE);
	free(key);
	return 0;
}

static struct dp_rt_path_unusable_key *
dp_test_nh_state_make_key(const char *interface,
			  const char *nexthop)
{
	struct dp_rt_path_unusable_key *key;
	struct dp_test_addr addr;

	key = calloc(1, sizeof(*key));
	dp_test_assert_internal(key != NULL);
	/* nexthop is allowed to be null */
	if (nexthop) {
		if (!dp_test_addr_str_to_addr(nexthop, &addr))
			dp_test_assert_internal(false);

		dp_test_assert_internal(addr.family == AF_INET ||
					addr.family == AF_INET6);

		key->type = DP_RT_PATH_UNUSABLE_KEY_INTF_NEXTHOP;
		key->nexthop.type = addr.family;
		memcpy(&key->nexthop.address, &addr.addr,
		       sizeof(key->nexthop.address));
	} else {
		key->type = DP_RT_PATH_UNUSABLE_KEY_INTF;
	}

	key->ifindex = dp_test_intf_name2index(interface);

	return key;

}

void dp_test_make_nh_unusable_other_thread(pthread_t *nh_unusable_thread,
					   const char *interface,
					   const char *nexthop)
{
	struct dp_rt_path_unusable_key *key;

	key = dp_test_nh_state_make_key(interface, nexthop);
	/*
	 * Spin up a thread to make the nh unusable
	 */
	if (pthread_create(nh_unusable_thread, NULL, nh_unusable, key) < 0)
		dp_test_abort_internal();
}

void dp_test_make_nh_usable_other_thread(pthread_t *nh_unusable_thread,
					 const char *interface,
					 const char *nexthop)
{
	struct dp_rt_path_unusable_key *key;

	key = dp_test_nh_state_make_key(interface, nexthop);
	/*
	 * Spin up a thread to make the nh unusable
	 */
	if (pthread_create(nh_unusable_thread, NULL, nh_usable, key) < 0)
		dp_test_abort_internal();
}

void dp_test_tcase_mark(bool begin, const char *name)
{
	RTE_LOG(INFO, DATAPLANE, "----- %-5s %-40s -----\n",
		begin ? "BEGIN" : "END", name);
}

uint32_t dp_test_sys_uptime(void)
{
	struct sysinfo s_info;
	uint32_t error = sysinfo(&s_info);

	if (error != 0)
		dp_test_abort_internal();

	return s_info.uptime;
}
