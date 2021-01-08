/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane NPTv6 tests
 */

#include <libmnl/libmnl.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"
#include "netinet6/ip6_funcs.h"
#include "netinet6/in6_var.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_cmd_state.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_lib_internal.h"
#include "dp_test_str.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"
#include "dp_test_npf_sess_lib.h"
#include "dp_test_npf_fw_lib.h"
#include "dp_test_npf_portmap_lib.h"
#include "dp_test_npf_nat_lib.h"

/*************************************************************************
 *
 * NPTv6 Test cases
 *
 * nptv6_1   -- Tests nptv6 inside->outside and outside->inside translation
 *             on an set of prefixes
 * nptv6_2   -- Tests the two flavours of prefix copy
 * nptv6_3   -- Tests iid_zero function
 * nptv6_4   -- Tests dataplane nptv6 with two /64 prefixes
 * nptv6_5   -- Tests dataplane nptv6 with two /48 prefixes
 * nptv6_6   -- Tests dataplane nptv6 /64 internal, /48 external.
 *             Non-overlapping internal prefix is 0.
 * nptv6_8   -- Add and delete multiple nptv6 translators.
 * nptv6_9   -- Tests dataplane nptv6 ICMP error generation.
 * nptv6_9b  -- Tests dataplane nptv6 ICMP errors can be disabled.
 * nptv6_10  -- Tests dataplane nptv6.  External to internal, with inner
 *             ICMPv6 destination unreachable packet.
 * nptv6_11  -- Tests dataplane nptv6.  Internal to external, with inner
 *             ICMPv6 destination unreachable packet.
 * nptv6_12  -- Tests generation of ICMP Parameter Problem if IID is zero
 *              after NPTv6 mapping.
 * nptv6_13  -- Tests ICMP error generation when inside prefix is shorter
 *              than outside prefix, and bits are set in the non-overlapping
 *               prefix.
 * nptv6_14  -- Tests dataplane nptv6 /48 internal, /64 external, but with no
 *              bits set in the source address that correspond to the
 *              non-overlapping prefix.
 *
 * To run all or one test case:
 *
 * make -j4 dataplane_test_run CK_RUN_SUITE=dp_test_npf_nptv6.c
 * make -j4 dataplane_test_run CK_RUN_CASE=nptv6_1
 *
 *************************************************************************/


/*
 * Simple array to string
 */
#define NSTRS  10
#define STR_SZ 100

static char strs[NSTRS][STR_SZ];
static uint cur;

/*
 * Create a string from a byte array
 */
static char *array_str(uint8_t *array, uint len)
{
	char *str = strs[cur];
	uint i, l;

	if (++cur >= NSTRS)
		cur = 0;

	str[0] = '\n';

	if (len > (STR_SZ/2 - 1))
		return str;

	l = 0;
	for (i = 0; i < len; i++) {
		if (i > 0 && !(i&1))
			l += snprintf(str+l, STR_SZ-l, ":");
		l += snprintf(str+l, STR_SZ-l, "%02X", array[i]);
	}

	return str;
}

/*
 * Copies masklen bits from src to dest.  Only copies significant bits in
 * order to leave host bits unchanged.
 */
static void
prefix_cpy(uint8_t *dest, const uint8_t *src, uint8_t masklen)
{
	int i, j;

	/* Copy whole bytes */
	for (i = masklen, j = 0; i >= 8; i -= 8, j++)
		dest[j] = src[j];

	/* Copy partial byte */
	if (i > 0) {
		uint8_t mask = 0xffu << (8-i);
		dest[j] = (src[j] & mask) | (dest[j] & ~mask);
	}
}

/*
 * The prefix_cpy used in npf_ext_nptv6.c
 */
static void
prefix_cpy2(struct in6_addr *dest, const struct in6_addr *src,
	    uint8_t prefix_len)
{
	const uint32_t *s = src->s6_addr32;
	uint32_t *d = dest->s6_addr32;

	while (prefix_len >= 32) {
		*d++ = *s++;
		prefix_len -= 32;
	}

	if (prefix_len == 0)
		return;

	uint32_t m = htonl(~0ul << (32 - prefix_len));

	*d = (*s & m) | (*d & ~m);
}

/*
 * Fetch and display json for all nptv6 rprocs
 */
static void
dp_test_nptv6_show(void)
{
	json_object *jresp;
	char *response;
	const char *str;
	bool err;

	response = dp_test_console_request_w_err("npf-op show nptv6",
						 &err, false);

	if (!response || err) {
		printf("  no response\n");
		return;
	}

	jresp = parse_json(response, parse_err_str, sizeof(parse_err_str));
	if (!jresp) {
		printf("  failed to parse json\n");
		return;
	}

	str = json_object_to_json_string_ext(jresp, JSON_C_TO_STRING_PRETTY);
	if (str)
		printf("%s\n", str);
	json_object_put(jresp);
}

/*
 * Create a prefix mask from a prefix length
 */
static void prefix_length2mask(uint8_t *a, uint alen, uint mask)
{
	uint i, b;

	/* Start at most significant byte */
	for (i = 0, b = mask; i < alen && b > 7; i++, b -= 8)
		a[i] = 0xff;

	/* partial byte */
	if (b)
		a[i] = a[i] | (0xFF << (8-b));
}

/*
 * One's complement sum. returns number1 + number2
 */
static unsigned short
add1(unsigned short  number1, unsigned short  number2)
{
	unsigned int    result;

	result = number1;
	result += number2;

	while (result > 0xFFFF)
		result = result + 1 - 0x10000;

	return result;
}
/*
 * One's complement difference.  returns number1 - number2
 */
static unsigned short
sub1(unsigned short  number1, unsigned short  number2)
{
	return add1(number1, ~number2);
}

/*
 * return one's complement sum of an array of numbers
 *
 * count is the number of ushorts in the prefix, e.g. 3 for /48, 4 for /64
 * etc.
 */
static unsigned short
sum1(unsigned short *numbers, int count)
{
	unsigned int    result;

	result = *numbers++;
	while (--count > 0)
		result += *numbers++;

	while (result > 0xFFFF)
		result = result + 1 - 0x10000;

	return result;
}

/*
 * Get initial adjustment word based on prefix lengths.
 */
static uint
dp_test_nptv6_adj_word_init(uint intl_plen, uint extl_plen)
{
	uint plen = MAX(intl_plen, extl_plen);

	if (plen > 112)
		return 0;

	if (plen <= 48)
		return 3;

	/* Round up to multiple of 16 if necessary */
	if (plen & 0xF)
		plen = ((plen >> 4) + 1) << 4;

	return plen >> 4;
}

/*
 * Determine which uint16_t word to add/subtract the adjustment to/from per
 * address mapping.  We start at the word determined from
 * dp_test_nptv6_adj_word_init, and choose the first word that is not 0xFFFF.
 *
 * A translated address never has 0xFFFF in the adjustment word position, so
 * we can safely do this determination in both pre and post NPTv6 addresses.
 *
 * adj_word will be at least 3. We also ensure it is never greater than 6, to
 * avoid overwriting the least-significant word in the address.
 */
static uint
dp_test_nptv6_adj_word(uint adj_word, npf_addr_t *addr)
{
	if (adj_word == 0)
		return 0;

	/*
	 * for /48 prefix length we do not look past 4th word
	 */
	if (adj_word == 3 && addr->s6_addr16[3] == 0xFFFF)
		return 0;

	for (; adj_word < 7; adj_word++) {
		if (addr->s6_addr16[adj_word] != 0xFFFF)
			return adj_word;
	}
	return 0;
}

/*
 *
 * [3.1] When an NPTv6 Translator is configured, the translation function
 * first ensures that the internal and external prefixes are the same length,
 * extending the shorter of the two with zeroes if necessary.
 *
 * They are then zero-extended to /64 for the purposes of a calculation.  The
 * translation function calculates the one's complement sum of the 16-bit
 * words of the /64 external prefix and the /64 internal prefix.  It then
 * calculates the difference between these values: internal minus external.
 *
 * This value, called the "adjustment", is effectively constant for the
 * lifetime of the NPTv6 Translator configuration and is used in per-datagram
 * processing.
 */
static uint16_t
dp_test_nptv6_adjustment(npf_addr_t *inner_pfx, uint inner_mask,
			 npf_addr_t *outer_pfx, uint outer_mask)
{
	npf_addr_t inner = IN6ADDR_ANY_INIT; /* All zeros */
	npf_addr_t outer = IN6ADDR_ANY_INIT; /* All zeros */

	/* Copy prefixs. Host parts remain zero. */
	prefix_cpy(inner.s6_addr, inner_pfx->s6_addr, inner_mask);
	prefix_cpy(outer.s6_addr, outer_pfx->s6_addr, outer_mask);

	/* adjustment is calculated from most-significant 64 bits */
	uint16_t inner64 = sum1(&inner.s6_addr16[0], 4);
	uint16_t outer64 = sum1(&outer.s6_addr16[0], 4);
	uint16_t adjustment = sub1(inner64, outer64);

	return adjustment;
}

static void _dp_test_equal_addr(npf_addr_t *a1, npf_addr_t *a2,
				uint alen, const char *file, int line)
{
	uint i;

	for (i = 0; i < alen; i++) {
		_dp_test_fail_unless(a1->s6_addr[i] == a2->s6_addr[i],
				     file, line,
				     "addresses differ at byte %u of %u,"
				     " 0x%02X != 0x%02X",
				     i+1, alen,
				     a1->s6_addr[i], a2->s6_addr[i]);
	}
}

#define dp_test_equal_addr(a1, a2, l)				\
	_dp_test_equal_addr(a1, a2, l,  __FILE__, __LINE__)


/*
 * NPTv6 specifies that the shorter IPv6 prefix is zero-extended to match the
 * longer prefix.  This implies that the bits in the address with the shorter
 * prefix that correspond to the zero-extended bits must be zero since they
 * would otherwise get lost in the mapping.
 *
 *   a1 = FD01:0203:0405:0001:0000::1234/64
 *   a2 = 2001:0DB8:0001:0000:D550::1234/48
 *
 * mask will evaluate to:
 *      0000:0000:0000:FFFF:0000::0000
 *
 * and the shorter address masked with mask will be all zeros, so valid
 *
 *
 * The following are *not* valid for NPTv6:
 *
 *   a1 = FD01:0203:0405:0001:0000::1234/64
 *   a2 = 2001:0DB8:0001:0002:D550::1234/48
 *
 * Note, we can pre-compute the mask at config time.
 */
static bool
nptv6_validate_addresses(npf_addr_t *a1, uint p1, npf_addr_t *a2, uint p2)
{
	if (p1 == p2)
		return true;

	npf_addr_t m1 = IN6ADDR_ANY_INIT;
	npf_addr_t m2 = IN6ADDR_ANY_INIT;
	npf_addr_t *shorter = p1 < p2 ? a1 : a2;
	uint8_t mask;
	uint i;

	prefix_length2mask(m1.s6_addr, 16, p1);
	prefix_length2mask(m2.s6_addr, 16, p2);

	for (i = 0; i < 16 && (m1.s6_addr[i] || m2.s6_addr[i]); i++) {
		mask = m1.s6_addr[i] ^ m2.s6_addr[i];

		if (shorter->s6_addr[i] & mask)
			return false;
	}
	return true;
}

/*
 * NPTv6 translation of addr.  Store result in trans.  Compare result with
 * exp, if non-null.
 *
 * addr  - Address we are translating
 * pfx   - Translation prefix
 * trans - Address to store the translation in
 * exp   - Expected address
 * masklen - Length of the prefix in pfx
 */
static void
_dp_test_nptv6(npf_addr_t *addr, npf_addr_t *pfx, npf_addr_t *trans,
	       npf_addr_t *exp, uint masklen, uint adj_word,
	       uint16_t adjustment, bool inner_to_outer,
	       const char *file, int line)
{
	/*
	 * addr and exp should checksum to the same value
	 */
	uint16_t addr_sum, exp_sum;

	addr_sum = sum1(&addr->s6_addr16[0], 8);
	if (exp)
		exp_sum  = sum1(&exp->s6_addr16[0], 8);

	/*
	 * Which uint16_t word in the address will be adjust?
	 */
	adj_word = dp_test_nptv6_adj_word(adj_word, addr);

	if (addr->s6_addr16[3] == 0xFFFF && masklen == 48)
		_dp_test_fail_unless(adj_word == 0, file, line,
				     "adj_word expected 0, got %u",
				     adj_word);
	else
		_dp_test_fail_unless(adj_word != 0, file, line,
				     "adj_word expected non-zero, for 0");

	if (adj_word == 0)
		return;

	/*
	 * Copy addr to trans (only really need the host bits, but copying
	 * all is probably faster)
	 */
	memcpy(trans->s6_addr, addr->s6_addr, 16);

	/* Change prefix */
	prefix_cpy(trans->s6_addr, pfx->s6_addr, masklen);

	if (inner_to_outer)
		trans->s6_addr16[adj_word] = add1(addr->s6_addr16[adj_word],
						  adjustment);
	else
		trans->s6_addr16[adj_word] = sub1(addr->s6_addr16[adj_word],
						  adjustment);

	if (trans->s6_addr16[adj_word] == 0xFFFF)
		trans->s6_addr16[adj_word] = 0;

	if (exp) {
		/* Verify that trans_addr now equals extl_addr */
		_dp_test_equal_addr(trans, exp, 16, file, line);

		/* Verify that checksums are the same */
		_dp_test_fail_unless(
			addr_sum == exp_sum, file, line,
			"addr cksum 0x%04X != exp cksum 0x%04X",
			addr_sum, exp_sum);
	}

}

/*
 * Perform an nptv6 translation of addr_str.  Store result in new_str.
 * Returns pointer to new_str if sucessfull, else NULL.
 *
 * Assumes new_str is at least INET6_ADDRSTRLEN in length.
 */
static char *
dp_test_nptv6_str(const char *addr_str, uint addr_pfxlen,
		  const char *trans_str, uint trans_pfxlen,
		  char *new_str, bool to_ext)
{
	npf_addr_t addr, trans, new;
	uint16_t adjustment;
	uint adj_word;
	int rc;

	rc = inet_pton(AF_INET6, addr_str, &addr);
	if (rc != 1)
		return NULL;

	rc = inet_pton(AF_INET6, trans_str, &trans);
	if (rc != 1)
		return NULL;

	adj_word = dp_test_nptv6_adj_word_init(addr_pfxlen, trans_pfxlen);

	/* Get adjustment value.  Only need do this once */
	if (to_ext)
		adjustment = dp_test_nptv6_adjustment(&addr, addr_pfxlen,
						      &trans, trans_pfxlen);
	else
		adjustment = dp_test_nptv6_adjustment(&trans, trans_pfxlen,
						      &addr, addr_pfxlen);

	memset(&new, 0, sizeof(npf_addr_t));

	_dp_test_nptv6(&addr, &trans, &new, NULL,
		       MAX(addr_pfxlen, trans_pfxlen),
		       adj_word, adjustment, to_ext,
		       __FILE__, __LINE__);

	char *rv = (char *)inet_ntop(AF_INET6, new.s6_addr,
				     new_str, INET6_ADDRSTRLEN);

	return rv;
}

DP_DECL_TEST_SUITE(npf_nptv6);

/*
 * nptv6_1 -- Tests nptv6 inside->outside and outside->inside translation on
 * an set of prefixes
 */
DP_DECL_TEST_CASE(npf_nptv6, nptv6_1, NULL, NULL);
DP_START_TEST(nptv6_1, test)
{
	uint i;

	struct test_addr {
		const char *intl;
		uint        intl_mask;
		const char *extl;
		uint        extl_mask;
	} test_addrs[] = {
		{
			"FD01:0203:0405:0001::1234",
			48,
			"2001:0DB8:0001:D550::1234",
			48
		},
		{
			"FD01:0203:0405:FFFF:0001::1234",
			48,
			"2001:0DB8:0001:FFFF:D550::1234",
			48
		},
		{
			"FD01:0203:0405:0001:0001::1234",
			64,
			"2001:0DB8:0001:0000:D551::1234",
			48
		},
		{
			"FD01:0203:0405:0000:0001::1234",
			48,
			"2001:0DB8:0001:0000:D550::1234",
			64
		}
	};

	for (i = 0; i < ARRAY_SIZE(test_addrs); i++) {
		npf_addr_t intl, extl, trans;
		npf_addr_t intl_pfx = IN6ADDR_ANY_INIT;
		npf_addr_t extl_pfx = IN6ADDR_ANY_INIT;
		uint adj_word;
		int rc;
		bool rv;
		uint16_t adjustment;

		rc = inet_pton(AF_INET6, test_addrs[i].intl, &intl);
		dp_test_fail_unless(rc == 1, "inet_pton intl %u", i);

		rc = inet_pton(AF_INET6, test_addrs[i].extl, &extl);
		dp_test_fail_unless(rc == 1, "inet_pton extl %u", i);

		rv = nptv6_validate_addresses(&intl, test_addrs[i].intl_mask,
					      &extl, test_addrs[i].extl_mask);
		dp_test_fail_unless(rv, "NPTv6 validation failed");

		/*
		 * Isolate prefixes for internal and external addresses These
		 * would usually be part of the PTv6 config.  We derive these
		 * from the test addresses.
		 */
		prefix_cpy(intl_pfx.s6_addr, intl.s6_addr,
			   test_addrs[i].intl_mask);
		prefix_cpy(extl_pfx.s6_addr, extl.s6_addr,
			   test_addrs[i].extl_mask);

		/* Get initial adjustment word. Only need do this once */
		adj_word = dp_test_nptv6_adj_word_init(test_addrs[i].intl_mask,
						       test_addrs[i].extl_mask);

		/* Get adjustment value.  Only need do this once */
		adjustment = dp_test_nptv6_adjustment(&intl,
						      test_addrs[i].intl_mask,
						      &extl,
						      test_addrs[i].extl_mask);

		uint masklen = MAX(test_addrs[i].intl_mask,
				   test_addrs[i].extl_mask);

		/* Internal to external */
		_dp_test_nptv6(&intl, &extl_pfx, &trans, &extl,
			       masklen, adj_word, adjustment, true,
			       __FILE__, __LINE__);

		/* External to internal */
		_dp_test_nptv6(&extl, &intl_pfx, &trans, &intl,
			       test_addrs[i].intl_mask,
			       adj_word, adjustment, false,
			       __FILE__, __LINE__);

	}


} DP_END_TEST;

/*
 * nptv6_2 -- Tests the two flavours of prefix copy
 */
DP_DECL_TEST_CASE(npf_nptv6, nptv6_2, NULL, NULL);
DP_START_TEST(nptv6_2, test)
{
	uint i;

	struct test_data {
		uint plen;
		const char *src;
		const char *dst;
		const char *exp;
	} data[] = {
		{4, "abcd:ef35:2345:6789::2", "::", "a000::"},
		{8, "abcd:ef35:2345:6789::2", "::", "ab00::"},
		{12, "abcd:ef35:2345:6789::2", "::", "abc0::"},
		{16, "abcd:ef35:2345:6789::2", "::", "abcd::"},
		{20, "abcd:ef35:2345:6789::2", "::", "abcd:e000::"},
		{24, "abcd:ef35:2345:6789::2", "::", "abcd:ef00::"},
		{28, "abcd:ef35:2345:6789::2", "::", "abcd:ef30::"},
		{32, "abcd:ef35:2345:6789::2", "::", "abcd:ef35::"},
		{36, "abcd:ef35:2345:6789::2", "::", "abcd:ef35:2000::"},
		{40, "abcd:ef35:2345:6789::2", "::", "abcd:ef35:2300::"},
		{44, "abcd:ef35:2345:6789::2", "::", "abcd:ef35:2340::"},
		{48, "abcd:ef35:2345:6789::2", "::", "abcd:ef35:2345::"},
		{52, "abcd:ef35:2345:6789::2", "::", "abcd:ef35:2345:6000::"},
		{56, "abcd:ef35:2345:6789::2", "::", "abcd:ef35:2345:6700::"},
		{60, "abcd:ef35:2345:6789::2", "::", "abcd:ef35:2345:6780::"},
		{64, "abcd:ef35:2345:6789::2", "::", "abcd:ef35:2345:6789::"},
		{65, "abcd:ef35:2345:6789:abcd::2", "::",
		 "abcd:ef35:2345:6789:8000::"},
		{68, "abcd:ef35:2345:6789:abcd::2", "::",
		 "abcd:ef35:2345:6789:a000::"},
		{71, "abcd:ef35:2345:6789:abcd::2", "::",
		 "abcd:ef35:2345:6789:aa00::"},
		{64, "abcd:ef35:2345:6789::2", "ffff:ffff:ffff:ffff:ffff::2",
		 "abcd:ef35:2345:6789:ffff::2"},
		{65, "abcd:ef35:2345:6789::2", "ffff:ffff:ffff:ffff:ffff::2",
		 "abcd:ef35:2345:6789:7fff::2"},
		{66, "abcd:ef35:2345:6789::2", "ffff:ffff:ffff:ffff:ffff::2",
		 "abcd:ef35:2345:6789:3fff::2"},
		{69, "abcd:ef35:2345:6789::2", "ffff:ffff:ffff:ffff:ffff::2",
		 "abcd:ef35:2345:6789:7ff::2"},
		{74, "abcd:ef35:2345:6789::2", "ffff:ffff:ffff:ffff:ffff::2",
		 "abcd:ef35:2345:6789:3f::2"},
	};

	for (i = 0; i < ARRAY_SIZE(data); i++) {
		struct in6_addr src, dst;
		struct in6_addr exp;
		int result;

		result = inet_pton(AF_INET6, data[i].src, &src);
		dp_test_assert_internal(result == 1);

		result = inet_pton(AF_INET6, data[i].exp, &exp);
		dp_test_assert_internal(result == 1);

		result = inet_pton(AF_INET6, data[i].dst, &dst);
		dp_test_assert_internal(result == 1);

		prefix_cpy(dst.s6_addr, src.s6_addr, data[i].plen);

		if (memcmp(dst.s6_addr, exp.s6_addr, 16) != 0) {
			dp_test_fail("prefix_cpy, 1=%u plen=%u, "
				     "expected %s, got %s",
				     i, data[i].plen,
				     array_str(exp.s6_addr, 16),
				     array_str(dst.s6_addr, 16));
		}

		result = inet_pton(AF_INET6, data[i].dst, &dst);
		dp_test_assert_internal(result == 1);

		prefix_cpy2(&dst, &src, data[i].plen);

		if (memcmp(dst.s6_addr, exp.s6_addr, 16) != 0) {
			dp_test_fail("prefix_cpy2, 1=%u plen=%u, "
				     "expected %s, got %s",
				     i, data[i].plen,
				     array_str(exp.s6_addr, 16),
				     array_str(dst.s6_addr, 16));

		}
	}

} DP_END_TEST;

static bool
iid_zero(const struct in6_addr *addr, uint prefix_len)
{
	const uint32_t *p = &addr->s6_addr32[3];
	uint iid_len = 128 - prefix_len;

	while (iid_len >= 32) {
		if (*p-- != 0)
			return false;
		iid_len -= 32;
	}

	if (likely(iid_len == 0))
		return true;

	uint32_t m = ~htonl(~0ul << iid_len);

	/* find bits that differ, and mask in network byte order */
	return (*p & m) == 0;
}

/*
 * nptv6_3 -- Tests iid_zero function
 */
DP_DECL_TEST_CASE(npf_nptv6, nptv6_3, NULL, NULL);
DP_START_TEST(nptv6_3, test)
{
	uint i;

	struct test_data {
		uint plen;
		const char *addr;
		bool exp;
	} data[] = {
		{4, "abcd:ef35:2345:6789::2", false},
		{48, "abcd:ef35:2345:6e00::", false},
		{52, "abcd:ef35:2345:6e00::", false},
		{56, "abcd:ef35:2345:6e00::", true},
		{64, "abcd:ef35:2345:6e00::", true},
		{53, "abcd:ef35:2345:6e00::", false},
		{54, "abcd:ef35:2345:6e00::", false},
		{55, "abcd:ef35:2345:6e00::", true},
	};

	for (i = 0; i < ARRAY_SIZE(data); i++) {
		struct in6_addr addr;
		int result;
		bool rv;

		result = inet_pton(AF_INET6, data[i].addr, &addr);
		dp_test_assert_internal(result == 1);

		rv = iid_zero(&addr, data[i].plen);


		dp_test_fail_unless(rv == data[i].exp, "expected %s",
				    data[i].exp ? "zero":"non-zero");
	}

} DP_END_TEST;

/*
 * Add nptv6 rule
 */
static void dp_test_npf_add_nptv6(const char *ifname,
				  rule_no_t rule_no,
				  const char *inside,
				  const char *outside,
				  bool icmperr)
{
	char rifname[IFNAMSIZ];
	const char *rg_name = "MYNPTV6";
	char str[12];

	dp_test_intf_real(ifname, rifname);

	str[0] = '\0';
	if (!icmperr)
		snprintf(str, sizeof(str), ",icmperr=no");

	/*
	 * Internal to external.  Match on internal prefix
	 */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut add nptv6-out:%s 10 src-addr=%s "
		"handle=nptv6(inside=%s,outside=%s%s)",
		rg_name, inside, inside, outside, str);

	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut attach interface:%s nptv6-out nptv6-out:%s",
		rifname, rg_name);
	dp_test_npf_commit();

	/*
	 * External to Internal.  Match on external prefix
	 */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut add nptv6-in:%s 10 dst-addr=%s "
		"handle=nptv6(inside=%s,outside=%s%s)",
		rg_name, outside, inside, outside, str);

	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut attach interface:%s nptv6-in nptv6-in:%s",
		rifname, rg_name);

	dp_test_npf_commit();

	/* Check that nptv6 feature node is now added to pipelines */
	dp_test_wait_for_pl_feat(ifname, "vyatta:ipv6-nptv6-in",
				 "ipv6-validate");
	dp_test_wait_for_pl_feat(ifname, "vyatta:ipv6-nptv6-out",
				 "ipv6-out");
}

/*
 * Delete nptv6 rproc rule
 */
static void dp_test_npf_del_nptv6(const char *ifname, rule_no_t rule_no,
				  const char *inside, const char *outside)
{
	char rifname[IFNAMSIZ];
	const char *rg_name = "MYNPTV6";

	dp_test_intf_real(ifname, rifname);

	dp_test_npf_cmd_fmt(false,
			    "npf-ut detach interface:%s nptv6-out nptv6-out:%s",
			    rifname, rg_name);

	dp_test_npf_cmd_fmt(false,
			    "npf-ut detach interface:%s nptv6-in nptv6-in:%s",
			    rifname, rg_name);

	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(false,
			    "npf-ut delete nptv6-in:%s", rg_name);
	dp_test_npf_cmd_fmt(false,
			    "npf-ut delete nptv6-out:%s", rg_name);

	dp_test_npf_commit();
}

/*
 * Not really a cleanup.  Just check the nptv6 feature nodes have been
 * removed.
 */
static void dp_test_npf_nptv6_cleanup(const char *ifname)
{
	dp_test_wait_for_pl_feat_gone(ifname, "vyatta:ipv6-nptv6-in",
				      "ipv6-validate");
	dp_test_wait_for_pl_feat_gone(ifname, "vyatta:ipv6-nptv6-out",
				      "ipv6-out");
}

static void
dp_test_npf_show_rules(const char *rstype)
{
	json_object *jresp;
	char cmd[TEST_MAX_CMD_LEN];
	char *response;
	bool err;

	snprintf(cmd, sizeof(cmd), "npf-op show all: %s", rstype);

	response = dp_test_console_request_w_err(cmd, &err, false);
	if (!response || err) {
		dp_test_fail("no response from dataplane");
		return;
	}

	jresp = parse_json(response, parse_err_str, sizeof(parse_err_str));
	free(response);

	if (!jresp) {
		dp_test_fail("failed to parse response");
		return;
	}

	const char *str = json_object_to_json_string_ext(
		jresp, JSON_C_TO_STRING_PRETTY);
	if (str)
		printf("%s\n", str);
}

/*
 * nptv6_4
 *
 *                   internal         external
 *                             +-----+
 * host1  fd01:203:405:1::/64  |     | 2001:db8:1::1/64            host2
 * .2   -----------------------| uut |---------------------------- .2
 *                      dp1T0  |     | dp2T1
 *                             +-----+
 *
 * NPTv6: fd01:203:405:1::/64 is mapped to 2001:db8:2::1/64
 *
 *                                  ---> out, match
 *                                            src-addr  fd01:203:405:1::/64
 *
 *                                  <--- in,  match
 *                                            src-addr !fd01:203:405:1::/64
 *                                            dst-addr  2001:db8:2::/64
 *
 * Pkt 1, Internal-to-external:     --->
 *        Int: fd01:203:405:1::2    -> 2001:DB8:1::2
 *        Ext: 2001:DB8:2:0:d550::2 -> 2001:DB8:1::2
 *
 * Pkt 2, External-to-internal:     <---
 *        Ext: 2001:DB8:1::2        -> 2001:DB8:2:0:d550::2
 *        Int: 2001:DB8:1::2        -> fd01:203:405:1::2
 */
DP_DECL_TEST_CASE(npf_nptv6, nptv6_4, NULL, NULL);
DP_START_TEST(nptv6_4, test)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;
	struct rte_mbuf *exp_pak;

	/*
	 * int_addr: Address on internal network
	 * ext_addr: The NPTv6 mapping of int_addr
	 */
	const char *int_addr = "fd01:203:405:1::2";
	char ext_addr[INET6_ADDRSTRLEN];
	char *p;

	p = dp_test_nptv6_str(int_addr, 64, "2001:db8:2::", 64,
			      ext_addr, true);
	dp_test_fail_unless(p, "Failed to map %s", int_addr);

	/*
	 * Setup interfaces
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "10.10.1.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "10.10.2.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "fd01:203:405:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:db8:1::1/64");

	dp_test_netlink_add_neigh("dp1T0", int_addr,
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp1T1", "2001:db8:1::2",
				  "aa:bb:cc:dd:2:b1");

	/* Config nptv6 */
	dp_test_npf_add_nptv6("dp1T1", 10,
			      "fd01:203:405:1::/64",
			      "2001:db8:2::/64", true);

	struct dp_test_pkt_desc_t pkt1_pre = {
		.text       = "Internal to external, pre",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = int_addr,               /* <--- Orig */
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2001:DB8:1::2",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 49152,
				.dport = 80
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T1"
	};

	struct dp_test_pkt_desc_t pkt1_post = {
		.text       = "Internal to external, post",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = ext_addr,              /* <--- Translated */
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2001:DB8:1::2",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 49152,
				.dport = 80
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T1"
	};

	struct dp_test_pkt_desc_t pkt2_pre = {
		.text       = "External to internal, pre",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:DB8:1::2",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = ext_addr,             /* Before nptv6 */
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 80,
				.dport = 49152
			}
		},
		.rx_intf    = "dp1T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t pkt2_post = {
		.text       = "External to internal, post",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:DB8:1::2",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = int_addr,             /* After nptv6 */
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 80,
				.dport = 49152
			}
		},
		.rx_intf    = "dp1T1",
		.tx_intf    = "dp1T0"
	};

	char intl_intf[IFNAMSIZ];
	char extl_intf[IFNAMSIZ];

	dp_test_intf_real(pkt1_pre.rx_intf, intl_intf);
	dp_test_intf_real(pkt1_pre.tx_intf, extl_intf);

	/*****************************************************************
	 * Internal to external
	 *****************************************************************/

	test_pak = dp_test_v6_pkt_from_desc(&pkt1_pre);

	exp_pak = dp_test_v6_pkt_from_desc(&pkt1_post);
	test_exp = dp_test_exp_from_desc(exp_pak, &pkt1_post);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", test_exp);


	/*****************************************************************
	 * External to internal
	 *****************************************************************/

	test_pak = dp_test_v6_pkt_from_desc(&pkt2_pre);

	exp_pak = dp_test_v6_pkt_from_desc(&pkt2_post);
	test_exp = dp_test_exp_from_desc(exp_pak, &pkt2_post);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T1", test_exp);

	if (0) {
		dp_test_npf_show_rules("nptv6-in");
		dp_test_npf_show_rules("nptv6-out");
	}
	if (0)
		dp_test_nptv6_show();

	/*
	 * Cleanup
	 */
	dp_test_npf_del_nptv6("dp1T1", 10,
			      "fd01:203:405:1::/64",
			      "2001:db8:2::/64");

	dp_test_npf_cleanup();
	dp_test_npf_nptv6_cleanup("dp1T1");

	dp_test_netlink_del_neigh("dp1T0", int_addr,
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp1T1", "2001:db8:1::2",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "10.10.1.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "fd01:203:405:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:db8:1::1/64");

} DP_END_TEST;

/*
 * nptv6_5 -- /48 prefix lengths
 *
 *                        internal         external
 *                                  +-----+
 * host1       fd01:203:405:1::1/48 |     | 2001:db8:1::1/48            host2
 * .2   ----------------------------| uut |---------------------------- .2
 *                           dp1T0  |     | dp2T1
 *                                  +-----+
 *
 */
DP_DECL_TEST_CASE(npf_nptv6, nptv6_5, NULL, NULL);
DP_START_TEST(nptv6_5, test)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;
	struct rte_mbuf *exp_pak;

	/*
	 * Setup interfaces
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "10.10.1.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "10.10.2.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "fd01:203:405:1::1/48");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:db8:1::1/48");

	dp_test_netlink_add_neigh("dp1T0", "fd01:203:405:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp1T1", "2001:db8:1::2",
				  "aa:bb:cc:dd:2:b1");

	/* Config nptv6 */
	dp_test_npf_add_nptv6("dp1T1", 10,
			      "fd01:203:405::/48",
			      "2001:db8:1::/48", true);

	struct dp_test_pkt_desc_t pkt1_pre = {
		.text       = "Internal to external, pre",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "FD01:203:405:1::2",  /* <--- Orig */
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2001:DB8:1::2",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 49152,
				.dport = 80
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T1"
	};

	struct dp_test_pkt_desc_t pkt1_post = {
		.text       = "Internal to external, post",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:DB8:1:d550::2",  /* <--- Translated */
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2001:DB8:1::2",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 49152,
				.dport = 80
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T1"
	};

	struct dp_test_pkt_desc_t pkt2_pre = {
		.text       = "External to internal, pre",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:DB8:1::2",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "2001:DB8:1:d550::2",  /* Before nptv6 */
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 80,
				.dport = 49152
			}
		},
		.rx_intf    = "dp1T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t pkt2_post = {
		.text       = "External to internal, post",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:DB8:1::2",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "FD01:203:405:1::2",  /* After nptv6 */
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 80,
				.dport = 49152
			}
		},
		.rx_intf    = "dp1T1",
		.tx_intf    = "dp1T0"
	};

	char intl_intf[IFNAMSIZ];
	char extl_intf[IFNAMSIZ];

	dp_test_intf_real(pkt1_pre.rx_intf, intl_intf);
	dp_test_intf_real(pkt1_pre.tx_intf, extl_intf);

	/*****************************************************************
	 * Internal to external
	 *****************************************************************/

	test_pak = dp_test_v6_pkt_from_desc(&pkt1_pre);

	exp_pak = dp_test_v6_pkt_from_desc(&pkt1_post);
	test_exp = dp_test_exp_from_desc(exp_pak, &pkt1_pre);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", test_exp);


	/*****************************************************************
	 * External to internal
	 *****************************************************************/

	test_pak = dp_test_v6_pkt_from_desc(&pkt2_pre);

	exp_pak = dp_test_v6_pkt_from_desc(&pkt2_post);
	test_exp = dp_test_exp_from_desc(exp_pak, &pkt2_pre);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T1", test_exp);

	if (0) {
		dp_test_npf_show_rules("nptv6-in");
		dp_test_npf_show_rules("nptv6-out");
	}

	/*
	 * Cleanup
	 */
	dp_test_npf_del_nptv6("dp1T1", 10,
			      "fd01:203:405::/48",
			      "2001:db8:1::/48");

	dp_test_npf_cleanup();
	dp_test_npf_nptv6_cleanup("dp1T1");

	dp_test_netlink_del_neigh("dp1T0", "fd01:203:405:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp1T1", "2001:db8:1::2",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "10.10.1.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "fd01:203:405:1::1/48");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:db8:1::1/48");

} DP_END_TEST;

/*
 * nptv6_6 -- /64 internal, /48 external.  Non-overlapping internal prefix is
 * 0.
 *
 *                        internal         external
 *                                  +-----+
 * host1       fd01:203:405::1/64   |     | 2001:db8:1::1/48            host2
 * .2   ----------------------------| uut |---------------------------- .2
 *                           dp1T0  |     | dp2T1
 *                                  +-----+
 *
 */
DP_DECL_TEST_CASE(npf_nptv6, nptv6_6, NULL, NULL);
DP_START_TEST(nptv6_6, test)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;
	struct rte_mbuf *exp_pak;

	/*
	 * Setup interfaces
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "10.10.1.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "10.10.2.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "fd01:203:405::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:db8:1::1/48");

	dp_test_netlink_add_neigh("dp1T0", "fd01:203:405::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp1T1", "2001:db8:1::2",
				  "aa:bb:cc:dd:2:b1");

	/* Config nptv6 */
	dp_test_npf_add_nptv6("dp1T1", 10,
			      "fd01:203:405::/64",
			      "2001:db8:1::/48", true);

	struct dp_test_pkt_desc_t pkt1_pre = {
		.text       = "Internal to external, pre",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "FD01:203:405::2",  /* <--- Orig */
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2001:DB8:1::2",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 49152,
				.dport = 80
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T1"
	};

	struct dp_test_pkt_desc_t pkt1_post = {
		.text       = "Internal to external, post",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:DB8:1:0:d54f::2",  /* <--- Translated */
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2001:DB8:1::2",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 49152,
				.dport = 80
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T1"
	};

	struct dp_test_pkt_desc_t pkt2_pre = {
		.text       = "External to internal, pre",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:DB8:1::2",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "2001:DB8:1:0:d54f::2",  /* Before nptv6 */
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 80,
				.dport = 49152
			}
		},
		.rx_intf    = "dp1T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t pkt2_post = {
		.text       = "External to internal, post",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:DB8:1::2",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "FD01:203:405::2",  /* After nptv6 */
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 80,
				.dport = 49152
			}
		},
		.rx_intf    = "dp1T1",
		.tx_intf    = "dp1T0"
	};

	char intl_intf[IFNAMSIZ];
	char extl_intf[IFNAMSIZ];

	dp_test_intf_real(pkt1_pre.rx_intf, intl_intf);
	dp_test_intf_real(pkt1_pre.tx_intf, extl_intf);

	/*****************************************************************
	 * Internal to external
	 *****************************************************************/

	test_pak = dp_test_v6_pkt_from_desc(&pkt1_pre);

	exp_pak = dp_test_v6_pkt_from_desc(&pkt1_post);
	test_exp = dp_test_exp_from_desc(exp_pak, &pkt1_pre);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", test_exp);


	/*****************************************************************
	 * External to internal
	 *****************************************************************/

	test_pak = dp_test_v6_pkt_from_desc(&pkt2_pre);

	exp_pak = dp_test_v6_pkt_from_desc(&pkt2_post);
	test_exp = dp_test_exp_from_desc(exp_pak, &pkt2_pre);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T1", test_exp);

	if (0) {
		dp_test_npf_show_rules("nptv6-in");
		dp_test_npf_show_rules("nptv6-out");
	}

	/*
	 * Cleanup
	 */
	dp_test_npf_del_nptv6("dp1T1", 10,
			      "fd01:203:405::/64",
			      "2001:db8:1::/48");

	dp_test_npf_cleanup();
	dp_test_npf_nptv6_cleanup("dp1T1");

	dp_test_netlink_del_neigh("dp1T0", "fd01:203:405::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp1T1", "2001:db8:1::2",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "10.10.1.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "fd01:203:405::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:db8:1::1/48");

} DP_END_TEST;

/*
 * Display json for three nptv6 instances
 */
DP_DECL_TEST_CASE(npf_nptv6, nptv6_8, NULL, NULL);
DP_START_TEST(nptv6_8, test)
{
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "fd01:203:405:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:db8:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "2001:db8:4::1/64");

	/* Config nptv6 */
	dp_test_npf_add_nptv6("dp1T1", 10,
			      "fd01:203:405:1::/64",
			      "2001:db8:1::/64", true);

	dp_test_npf_add_nptv6("dp1T0", 10,
			      "fd01:2::/64",
			      "2001:db8:2::/64", true);

	dp_test_npf_add_nptv6("dp1T0", 20,
			      "fd01:3::/48",
			      "2001:db8:3::/48", true);

	if (0)
		dp_test_nptv6_show();

	dp_test_npf_del_nptv6("dp1T1", 10,
			      "fd01:203:405:1::/64",
			      "2001:db8:1::/64");

	dp_test_npf_del_nptv6("dp1T0", 10,
			      "fd01:2::/64",
			      "2001:db8:2::/64");

	dp_test_npf_del_nptv6("dp1T0", 20,
			      "fd01:3::/48",
			      "2001:db8:3::/48");

	dp_test_npf_cleanup();
	dp_test_npf_nptv6_cleanup("dp1T1");
	dp_test_npf_nptv6_cleanup("dp1T0");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "fd01:203:405:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:db8:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "2001:db8:4::1/64");

} DP_END_TEST;

/*
 * Initial internal-to-external packet is dropped, and an ICMPv6 destination
 * unreachable is generated by the translator and sent to originator.
 */
DP_DECL_TEST_CASE(npf_nptv6, nptv6_9, NULL, NULL);
DP_START_TEST(nptv6_9, test)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;
	struct rte_mbuf *exp_pak;

	/*
	 * Setup interfaces
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "10.10.1.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "10.10.2.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "fd01:203:405:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:db8:1::1/64");

	dp_test_netlink_add_neigh("dp1T0",
				  "fd01:203:405:1:ffff:ffff:ffff:ffff",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp1T1", "2001:db8:1::2",
				  "aa:bb:cc:dd:2:b1");

	/* Config nptv6 */
	dp_test_npf_add_nptv6("dp1T1", 10,
			      "fd01:203:405:1::/64",
			      "2001:db8:1::/64", true);

	struct dp_test_pkt_desc_t pkt1_pre = {
		.text	    = "Internal to external, pre",
		.len	    = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src	    = "fd01:203:405:1:ffff:ffff:ffff:ffff",
		.l2_src	    = "aa:bb:cc:dd:1:a1",
		.l3_dst	    = "2001:DB8:1::2",
		.l2_dst	    = "aa:bb:cc:dd:2:b1",
		.proto	    = IPPROTO_UDP,
		.l4	    = {
			.udp = {
				.sport = 49152,
				.dport = 80
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T1"
	};


	char intl_intf[IFNAMSIZ];
	char extl_intf[IFNAMSIZ];

	dp_test_intf_real(pkt1_pre.rx_intf, intl_intf);
	dp_test_intf_real(pkt1_pre.tx_intf, extl_intf);

	/*****************************************************************
	 * Internal to external
	 *****************************************************************/

	test_pak = dp_test_v6_pkt_from_desc(&pkt1_pre);

	struct ip6_hdr *inner_ip = ip6hdr(test_pak);
	struct icmp6_hdr *icmp6;
	int len = 116 - sizeof(struct icmp6_hdr) - sizeof(struct ip6_hdr);

	exp_pak = dp_test_create_icmp_ipv6_pak("fd01:203:405:1::1",
					       pkt1_pre.l3_src,
					       ICMP6_DST_UNREACH,
					       ICMP6_DST_UNREACH_ADDR,
					       0, 1, &len, inner_ip,
					       NULL, &icmp6);

	test_exp = dp_test_exp_create_m(NULL, 1);
	dp_test_exp_set_pak_m(test_exp, 0, exp_pak);

	inner_ip = (struct ip6_hdr *)(icmp6 + 1);
	inner_ip->ip6_hlim--;
	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = dp_test_ipv6_icmp_cksum(
		test_exp->exp_pak[0], ip6hdr(test_exp->exp_pak[0]),
		icmp6);
	dp_test_pktmbuf_eth_init(test_exp->exp_pak[0], "aa:bb:cc:dd:1:a1",
				 dp_test_intf_name2mac_str("dp1T0"),
				 RTE_ETHER_TYPE_IPV6);

	dp_test_exp_set_oif_name(test_exp, "dp1T0");
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", test_exp);


	if (0) {
		dp_test_npf_show_rules("nptv6-in");
		dp_test_npf_show_rules("nptv6-out");
	}
	if (0)
		dp_test_nptv6_show();

	/*
	 * Cleanup
	 */
	dp_test_npf_del_nptv6("dp1T1", 10,
			      "fd01:203:405:1::/64",
			      "2001:db8:1::/64");

	dp_test_npf_cleanup();
	dp_test_npf_nptv6_cleanup("dp1T1");

	dp_test_netlink_del_neigh("dp1T0",
				  "fd01:203:405:1:ffff:ffff:ffff:ffff",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp1T1", "2001:db8:1::2",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "10.10.1.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "fd01:203:405:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:db8:1::1/64");

} DP_END_TEST;

/*
 * Initial internal-to-external packet is dropped, and an ICMPv6 destination
 * unreachable is detected but *not* generated.
 */
DP_DECL_TEST_CASE(npf_nptv6, nptv6_9b, NULL, NULL);
DP_START_TEST(nptv6_9b, test)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;
	struct rte_mbuf *exp_pak;

	/*
	 * Setup interfaces
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "10.10.1.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "10.10.2.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "fd01:203:405:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:db8:1::1/64");

	dp_test_netlink_add_neigh("dp1T0",
				  "fd01:203:405:1:ffff:ffff:ffff:ffff",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp1T1", "2001:db8:1::2",
				  "aa:bb:cc:dd:2:b1");

	/* Config nptv6 */
	dp_test_npf_add_nptv6("dp1T1", 10,
			      "fd01:203:405:1::/64",
			      "2001:db8:1::/64", false);

	struct dp_test_pkt_desc_t pkt1_pre = {
		.text	    = "Internal to external, pre",
		.len	    = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src	    = "fd01:203:405:1:ffff:ffff:ffff:ffff",
		.l2_src	    = "aa:bb:cc:dd:1:a1",
		.l3_dst	    = "2001:DB8:1::2",
		.l2_dst	    = "aa:bb:cc:dd:2:b1",
		.proto	    = IPPROTO_UDP,
		.l4	    = {
			.udp = {
				.sport = 49152,
				.dport = 80
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T1"
	};


	char intl_intf[IFNAMSIZ];
	char extl_intf[IFNAMSIZ];

	dp_test_intf_real(pkt1_pre.rx_intf, intl_intf);
	dp_test_intf_real(pkt1_pre.tx_intf, extl_intf);

	/*****************************************************************
	 * Internal to external
	 *****************************************************************/

	test_pak = dp_test_v6_pkt_from_desc(&pkt1_pre);

	struct ip6_hdr *inner_ip = ip6hdr(test_pak);
	struct icmp6_hdr *icmp6;
	int len = 116 - sizeof(struct icmp6_hdr) - sizeof(struct ip6_hdr);

	exp_pak = dp_test_create_icmp_ipv6_pak("fd01:203:405:1::1",
					       pkt1_pre.l3_src,
					       ICMP6_DST_UNREACH,
					       ICMP6_DST_UNREACH_ADDR,
					       0, 1, &len, inner_ip,
					       NULL, &icmp6);

	test_exp = dp_test_exp_create_m(NULL, 1);
	dp_test_exp_set_pak_m(test_exp, 0, exp_pak);

	inner_ip = (struct ip6_hdr *)(icmp6 + 1);
	inner_ip->ip6_hlim--;
	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = dp_test_ipv6_icmp_cksum(
		test_exp->exp_pak[0], ip6hdr(test_exp->exp_pak[0]),
		icmp6);
	dp_test_pktmbuf_eth_init(test_exp->exp_pak[0], "aa:bb:cc:dd:1:a1",
				 dp_test_intf_name2mac_str("dp1T0"),
				 RTE_ETHER_TYPE_IPV6);

	dp_test_exp_set_oif_name(test_exp, "dp1T0");
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", test_exp);


	if (0) {
		dp_test_npf_show_rules("nptv6-in");
		dp_test_npf_show_rules("nptv6-out");
	}
	if (0)
		dp_test_nptv6_show();

	/*
	 * Cleanup
	 */
	dp_test_npf_del_nptv6("dp1T1", 10,
			      "fd01:203:405:1::/64",
			      "2001:db8:1::/64");

	dp_test_npf_cleanup();
	dp_test_npf_nptv6_cleanup("dp1T1");

	dp_test_netlink_del_neigh("dp1T0",
				  "fd01:203:405:1:ffff:ffff:ffff:ffff",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp1T1", "2001:db8:1::2",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "10.10.1.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "fd01:203:405:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:db8:1::1/64");

} DP_END_TEST;

/*
 * External to internal ICMPv6 destination unreachable
 *
 *                   internal         external
 *                             +-----+
 * host1  fd01:203:405:1::/64  |     | 2001:db8:1::1/64            host2
 * .2   -----------------------| uut |---------------------------- .2
 *                      dp1T0  |     | dp2T1
 *                             +-----+
 *
 *                                  ---> out, match
 *                                            src-addr  fd01:203:405:1::/64
 *                                            dst-addr !fd01:203:405:1::/64
 *
 *                                  <--- in,  match
 *                                            src-addr !fd01:203:405:1::/64
 *                                            dst-addr  2001:db8:1::/64
 *
 * Pkt 1, Internal-to-external:     --->
 *        Int: fd01:203:405:1::2    -> 2001:DB8:1::2
 *        Ext: 2001:DB8:1:0:d550::2 -> 2001:DB8:1::2
 *
 * Pkt 2, External-to-internal:     <---
 *        Ext: 2001:DB8:1::2        -> 2001:DB8:1:0:d550::2
 *        Int: 2001:DB8:1::2        -> fd01:203:405:1::2
 */
DP_DECL_TEST_CASE(npf_nptv6, nptv6_10, NULL, NULL);
DP_START_TEST(nptv6_10, test)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;
	struct rte_mbuf *exp_pak;

	/*
	 * Setup interfaces
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "10.10.1.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "10.10.2.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "fd01:203:405:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:db8:1::1/64");

	dp_test_netlink_add_neigh("dp1T0", "fd01:203:405:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp1T1", "2001:db8:1::2",
				  "aa:bb:cc:dd:2:b1");

	/* Config nptv6 */
	dp_test_npf_add_nptv6("dp1T1", 10,
			      "fd01:203:405:1::/64",
			      "2001:db8:1::/64", true);

	struct dp_test_pkt_desc_t pkt1_pre = {
		.text       = "Internal to external, pre",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "fd01:203:405:1::2",          /* <--- Orig */
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2001:DB8:1::2",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 49152,
				.dport = 80
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T1"
	};

	struct dp_test_pkt_desc_t pkt1_post = {
		.text       = "Internal to external, post",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:DB8:1:0:d550::2",   /* <--- Translated */
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2001:DB8:1::2",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 49152,
				.dport = 80
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T1"
	};

	struct dp_test_pkt_desc_t pkt2_pre = {
		.text       = "External to internal, pre",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:DB8:1::2",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "2001:DB8:1:0:d550::2",  /* Before nptv6 */
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 80,
				.dport = 49152
			}
		},
		.rx_intf    = "dp1T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t pkt2_post = {
		.text       = "External to internal, post",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:DB8:1::2",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "FD01:203:405:1::2",  /* After nptv6 */
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 80,
				.dport = 49152
			}
		},
		.rx_intf    = "dp1T1",
		.tx_intf    = "dp1T0"
	};

	char intl_intf[IFNAMSIZ];
	char extl_intf[IFNAMSIZ];

	dp_test_intf_real(pkt1_pre.rx_intf, intl_intf);
	dp_test_intf_real(pkt1_pre.tx_intf, extl_intf);


	/*****************************************************************
	 * External to internal - ICMPv6 dest unreachable
	 *****************************************************************/

	struct rte_mbuf *inner_pak;
	struct ip6_hdr *inner_ip;
	struct icmp6_hdr *icmp6;
	int len = 68; /* orig pkt size = 40 + 8 + 20 */

	/*
	 * ICMPv6 packet before translator
	 */
	inner_pak = dp_test_v6_pkt_from_desc(&pkt1_post);
	inner_ip = ip6hdr(inner_pak);

	test_pak = dp_test_create_icmp_ipv6_pak(pkt2_pre.l3_src,
						pkt2_pre.l3_dst,
						ICMP6_DST_UNREACH,
						ICMP6_DST_UNREACH_ADDR,
						0, 1, &len, inner_ip,
						NULL, &icmp6);
	rte_pktmbuf_free(inner_pak);

	inner_ip = (struct ip6_hdr *)(icmp6 + 1);
	inner_ip->ip6_hlim--;
	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = dp_test_ipv6_icmp_cksum(
		test_pak, ip6hdr(test_pak), icmp6);

	dp_test_pktmbuf_eth_init(test_pak,
				 dp_test_intf_name2mac_str("dp1T1"),
				 pkt2_pre.l2_src,
				 RTE_ETHER_TYPE_IPV6);

	/*
	 * ICMPv6 packet after translator
	 */
	inner_pak = dp_test_v6_pkt_from_desc(&pkt1_pre);
	inner_ip  = ip6hdr(inner_pak);

	exp_pak = dp_test_create_icmp_ipv6_pak(pkt2_post.l3_src,
					       pkt2_post.l3_dst,
					       ICMP6_DST_UNREACH,
					       ICMP6_DST_UNREACH_ADDR,
					       0, 1, &len, inner_ip,
					       NULL, &icmp6);
	rte_pktmbuf_free(inner_pak);

	inner_ip = (struct ip6_hdr *)(icmp6 + 1);
	inner_ip->ip6_hlim--;
	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = dp_test_ipv6_icmp_cksum(
		exp_pak, ip6hdr(exp_pak), icmp6);

	dp_test_pktmbuf_eth_init(exp_pak,
				 pkt2_post.l2_dst,
				 dp_test_intf_name2mac_str("dp1T0"),
				 RTE_ETHER_TYPE_IPV6);

	test_exp = dp_test_exp_create_m(NULL, 1);
	dp_test_exp_set_pak_m(test_exp, 0, exp_pak);

	dp_test_ipv6_decrement_ttl(exp_pak);
	dp_test_exp_set_oif_name(test_exp, "dp1T0");
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);


	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T1", test_exp);

	if (0) {
		dp_test_npf_show_rules("nptv6-in");
		dp_test_npf_show_rules("nptv6-out");
	}

	/*
	 * Cleanup
	 */
	dp_test_npf_del_nptv6("dp1T1", 10,
			      "fd01:203:405:1::/64",
			      "2001:db8:1::/64");

	dp_test_npf_cleanup();
	dp_test_npf_nptv6_cleanup("dp1T1");

	dp_test_netlink_del_neigh("dp1T0", "fd01:203:405:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp1T1", "2001:db8:1::2",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "10.10.1.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "fd01:203:405:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:db8:1::1/64");

} DP_END_TEST;

/*
 * nptv6_11 -- Internal to external ICMPv6 destination unreachable
 *
 *                   internal         external
 *                             +-----+
 * host1  fd01:203:405:1::/64  |     | 2001:db8:1::1/64            host2
 * .2   -----------------------| uut |---------------------------- .2
 *                      dp1T0  |     | dp2T1
 *                             +-----+
 *
 *                                  ---> out, match
 *                                            src-addr  fd01:203:405:1::/64
 *                                            dst-addr !fd01:203:405:1::/64
 *
 *                                  <--- in,  match
 *                                            src-addr !fd01:203:405:1::/64
 *                                            dst-addr  2001:db8:1::/64
 *
 * Pkt 1, Internal-to-external:     --->
 *        Int: fd01:203:405:1::2    -> 2001:DB8:1::2
 *        Ext: 2001:DB8:1:0:d550::2 -> 2001:DB8:1::2
 *
 * Pkt 2, External-to-internal:     <---
 *        Ext: 2001:DB8:1::2        -> 2001:DB8:1:0:d550::2
 *        Int: 2001:DB8:1::2        -> fd01:203:405:1::2
 */
DP_DECL_TEST_CASE(npf_nptv6, nptv6_11, NULL, NULL);
DP_START_TEST(nptv6_11, test)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;
	struct rte_mbuf *exp_pak;

	/*
	 * Setup interfaces
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "10.10.1.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "10.10.2.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "fd01:203:405:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:db8:1::1/64");

	dp_test_netlink_add_neigh("dp1T0", "fd01:203:405:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp1T1", "2001:db8:1::2",
				  "aa:bb:cc:dd:2:b1");

	/* Config nptv6 */
	dp_test_npf_add_nptv6("dp1T1", 10,
			      "fd01:203:405:1::/64",
			      "2001:db8:1::/64", true);

	struct dp_test_pkt_desc_t pkt1_pre = {
		.text       = "Internal to external, pre",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "fd01:203:405:1::2",          /* <--- Orig */
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2001:DB8:1::2",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 49152,
				.dport = 80
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T1"
	};

	struct dp_test_pkt_desc_t pkt1_post = {
		.text       = "Internal to external, post",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:DB8:1:0:d550::2",   /* <--- Translated */
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2001:DB8:1::2",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 49152,
				.dport = 80
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T1"
	};

	struct dp_test_pkt_desc_t pkt2_pre = {
		.text       = "External to internal, pre",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:DB8:1::2",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "2001:DB8:1:0:d550::2",  /* Before nptv6 */
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 80,
				.dport = 49152
			}
		},
		.rx_intf    = "dp1T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t pkt2_post = {
		.text       = "External to internal, post",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:DB8:1::2",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "FD01:203:405:1::2",  /* After nptv6 */
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 80,
				.dport = 49152
			}
		},
		.rx_intf    = "dp1T1",
		.tx_intf    = "dp1T0"
	};

	char intl_intf[IFNAMSIZ];
	char extl_intf[IFNAMSIZ];

	dp_test_intf_real(pkt1_pre.rx_intf, intl_intf);
	dp_test_intf_real(pkt1_pre.tx_intf, extl_intf);

	/*****************************************************************
	 * Internal to external - ICMPv6 dest unreachable
	 *****************************************************************/

	struct rte_mbuf *inner_pak;
	struct ip6_hdr *inner_ip;
	struct icmp6_hdr *icmp6;
	int len = 68; /* orig pkt size = 40 + 8 + 20 */

	/*
	 * ICMPv6 packet before translator
	 */
	inner_pak = dp_test_v6_pkt_from_desc(&pkt2_post);
	inner_ip = ip6hdr(inner_pak);

	test_pak = dp_test_create_icmp_ipv6_pak(pkt1_pre.l3_src,
						pkt1_pre.l3_dst,
						ICMP6_DST_UNREACH,
						ICMP6_DST_UNREACH_ADDR,
						0, 1, &len, inner_ip,
						NULL, &icmp6);
	rte_pktmbuf_free(inner_pak);

	inner_ip = (struct ip6_hdr *)(icmp6 + 1);
	inner_ip->ip6_hlim--;
	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = dp_test_ipv6_icmp_cksum(
		test_pak, ip6hdr(test_pak), icmp6);

	dp_test_pktmbuf_eth_init(test_pak,
				 dp_test_intf_name2mac_str("dp1T0"),
				 pkt1_pre.l2_src,
				 RTE_ETHER_TYPE_IPV6);

	/*
	 * ICMPv6 packet after translator
	 */
	inner_pak = dp_test_v6_pkt_from_desc(&pkt2_pre);
	inner_ip  = ip6hdr(inner_pak);

	exp_pak = dp_test_create_icmp_ipv6_pak(pkt1_post.l3_src,
					       pkt1_post.l3_dst,
					       ICMP6_DST_UNREACH,
					       ICMP6_DST_UNREACH_ADDR,
					       0, 1, &len, inner_ip,
					       NULL, &icmp6);
	rte_pktmbuf_free(inner_pak);

	inner_ip = (struct ip6_hdr *)(icmp6 + 1);
	inner_ip->ip6_hlim--;
	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = dp_test_ipv6_icmp_cksum(
		exp_pak, ip6hdr(exp_pak), icmp6);

	dp_test_pktmbuf_eth_init(exp_pak,
				 pkt1_post.l2_dst,
				 dp_test_intf_name2mac_str("dp1T1"),
				 RTE_ETHER_TYPE_IPV6);

	test_exp = dp_test_exp_create_m(NULL, 1);
	dp_test_exp_set_pak_m(test_exp, 0, exp_pak);

	dp_test_ipv6_decrement_ttl(exp_pak);
	dp_test_exp_set_oif_name(test_exp, "dp1T1");
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);


	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", test_exp);

	if (0) {
		dp_test_npf_show_rules("nptv6-in");
		dp_test_npf_show_rules("nptv6-out");
	}

	/*
	 * Cleanup
	 */
	dp_test_npf_del_nptv6("dp1T1", 10,
			      "fd01:203:405:1::/64",
			      "2001:db8:1::/64");

	dp_test_npf_cleanup();
	dp_test_npf_nptv6_cleanup("dp1T1");

	dp_test_netlink_del_neigh("dp1T0", "fd01:203:405:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp1T1", "2001:db8:1::2",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "10.10.1.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "fd01:203:405:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:db8:1::1/64");

} DP_END_TEST;

/*
 * Tests that an ICMP Parameter Problem message is generated if the NPTv6
 * translation results in an IID of zero.
 */
DP_DECL_TEST_CASE(npf_nptv6, nptv6_12, NULL, NULL);
DP_START_TEST(nptv6_12, test)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;
	struct rte_mbuf *exp_pak;

	/*
	 * Setup interfaces
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "10.10.1.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "10.10.2.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "fd01:203:405:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:db8:1::1/64");

	dp_test_netlink_add_neigh("dp1T0",
				  "fd01:203:405:1:2aaf::",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp1T1", "2001:db8:1::2",
				  "aa:bb:cc:dd:2:b1");

	/* Config nptv6 */
	dp_test_npf_add_nptv6("dp1T1", 10,
			      "fd01:203:405:1::/64",
			      "2001:db8:1::/64", true);

	/*
	 * The first word of the inside address IID is 0xaf2a.  When this is
	 * added to the adjustment word the result is 0xffff, which is changed
	 * to 0x0, thus triggering an ICMP param problem.
	 */
	npf_addr_t intl, extl;
	uint16_t adj;
	ushort result;

	inet_pton(AF_INET6, "fd01:203:405:1::", &intl);
	inet_pton(AF_INET6, "2001:db8:1::", &extl);
	adj = dp_test_nptv6_adjustment(&intl, 64, &extl, 64);
	result = add1(adj, 0xaf2a);

	dp_test_fail_unless(result == 0xFFFF,
			    "adj 0x%04X + 0xaf2a = 0x%04X",
			    adj, result);

	struct dp_test_pkt_desc_t pkt1_pre = {
		.text	    = "Internal to external, pre",
		.len	    = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src	    = "fd01:203:405:1:2aaf::",
		.l2_src	    = "aa:bb:cc:dd:1:a1",
		.l3_dst	    = "2001:DB8:1::2",
		.l2_dst	    = "aa:bb:cc:dd:2:b1",
		.proto	    = IPPROTO_UDP,
		.l4	    = {
			.udp = {
				.sport = 49152,
				.dport = 80
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T1"
	};


	char intl_intf[IFNAMSIZ];
	char extl_intf[IFNAMSIZ];

	dp_test_intf_real(pkt1_pre.rx_intf, intl_intf);
	dp_test_intf_real(pkt1_pre.tx_intf, extl_intf);

	/*****************************************************************
	 * Internal to external
	 *****************************************************************/

	test_pak = dp_test_v6_pkt_from_desc(&pkt1_pre);

	struct ip6_hdr *inner_ip = ip6hdr(test_pak);
	struct icmp6_hdr *icmp6;
	int len = 116 - sizeof(struct icmp6_hdr) - sizeof(struct ip6_hdr);

	exp_pak = dp_test_create_icmp_ipv6_pak("fd01:203:405:1::1",
					       pkt1_pre.l3_src,
					       ICMP6_PARAM_PROB,
					       ICMP6_PARAMPROB_HEADER,
					       0, 1, &len, inner_ip,
					       NULL, &icmp6);

	test_exp = dp_test_exp_create_m(NULL, 1);
	dp_test_exp_set_pak_m(test_exp, 0, exp_pak);

	inner_ip = (struct ip6_hdr *)(icmp6 + 1);
	inner_ip->ip6_hlim--;
	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = dp_test_ipv6_icmp_cksum(
		test_exp->exp_pak[0], ip6hdr(test_exp->exp_pak[0]),
		icmp6);
	dp_test_pktmbuf_eth_init(test_exp->exp_pak[0], "aa:bb:cc:dd:1:a1",
				 dp_test_intf_name2mac_str("dp1T0"),
				 RTE_ETHER_TYPE_IPV6);

	dp_test_exp_set_oif_name(test_exp, "dp1T0");
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", test_exp);


	if (0) {
		dp_test_npf_show_rules("nptv6-in");
		dp_test_npf_show_rules("nptv6-out");
	}
	if (0)
		dp_test_nptv6_show();

	/*
	 * Cleanup
	 */
	dp_test_npf_del_nptv6("dp1T1", 10,
			      "fd01:203:405:1::/64",
			      "2001:db8:1::/64");

	dp_test_npf_cleanup();
	dp_test_npf_nptv6_cleanup("dp1T1");

	dp_test_netlink_del_neigh("dp1T0",
				  "fd01:203:405:1:2aaf::",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp1T1", "2001:db8:1::2",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "10.10.1.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "fd01:203:405:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:db8:1::1/64");

} DP_END_TEST;

/*
 * Tests ICMP error generation when inside prefix is shorter than outside
 * prefix, and bits are set in the non-overlapping prefix.
 */
DP_DECL_TEST_CASE(npf_nptv6, nptv6_13, NULL, NULL);
DP_START_TEST(nptv6_13, test)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;
	struct rte_mbuf *exp_pak;

	/*
	 * Setup interfaces
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "10.10.1.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "10.10.2.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "fd01:203:405:1::1/48");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:db8:1::1/64");

	dp_test_netlink_add_neigh("dp1T0",
				  "fd01:203:405:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp1T1", "2001:db8:1::2",
				  "aa:bb:cc:dd:2:b1");

	/* Config nptv6 */
	dp_test_npf_add_nptv6("dp1T1", 10,
			      "fd01:203:405::/48",
			      "2001:db8:1::/64", true);

	struct dp_test_pkt_desc_t pkt1_pre = {
		.text	    = "Internal to external, pre",
		.len	    = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src	    = "fd01:203:405:1::2",
		.l2_src	    = "aa:bb:cc:dd:1:a1",
		.l3_dst	    = "2001:DB8:1::2",
		.l2_dst	    = "aa:bb:cc:dd:2:b1",
		.proto	    = IPPROTO_UDP,
		.l4	    = {
			.udp = {
				.sport = 49152,
				.dport = 80
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T1"
	};


	char intl_intf[IFNAMSIZ];
	char extl_intf[IFNAMSIZ];

	dp_test_intf_real(pkt1_pre.rx_intf, intl_intf);
	dp_test_intf_real(pkt1_pre.tx_intf, extl_intf);

	/*****************************************************************
	 * Internal to external
	 *****************************************************************/

	test_pak = dp_test_v6_pkt_from_desc(&pkt1_pre);

	struct ip6_hdr *inner_ip = ip6hdr(test_pak);
	struct icmp6_hdr *icmp6;
	int len = 116 - sizeof(struct icmp6_hdr) - sizeof(struct ip6_hdr);

	exp_pak = dp_test_create_icmp_ipv6_pak("fd01:203:405:1::1",
					       pkt1_pre.l3_src,
					       ICMP6_DST_UNREACH,
					       ICMP6_DST_UNREACH_ADDR,
					       0, 1, &len, inner_ip,
					       NULL, &icmp6);

	test_exp = dp_test_exp_create_m(NULL, 1);
	dp_test_exp_set_pak_m(test_exp, 0, exp_pak);

	inner_ip = (struct ip6_hdr *)(icmp6 + 1);
	inner_ip->ip6_hlim--;
	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = dp_test_ipv6_icmp_cksum(
		test_exp->exp_pak[0], ip6hdr(test_exp->exp_pak[0]),
		icmp6);
	dp_test_pktmbuf_eth_init(test_exp->exp_pak[0], "aa:bb:cc:dd:1:a1",
				 dp_test_intf_name2mac_str("dp1T0"),
				 RTE_ETHER_TYPE_IPV6);

	dp_test_exp_set_oif_name(test_exp, "dp1T0");
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", test_exp);


	if (0) {
		dp_test_npf_show_rules("nptv6-in");
		dp_test_npf_show_rules("nptv6-out");
	}
	if (0)
		dp_test_nptv6_show();

	/*
	 * Cleanup
	 */
	dp_test_npf_del_nptv6("dp1T1", 10,
			      "fd01:203:405:1::/64",
			      "2001:db8:1::/64");

	dp_test_npf_cleanup();
	dp_test_npf_nptv6_cleanup("dp1T1");

	dp_test_netlink_del_neigh("dp1T0",
				  "fd01:203:405:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp1T1", "2001:db8:1::2",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "10.10.1.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "fd01:203:405:1::1/48");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:db8:1::1/64");

} DP_END_TEST;

/*
 * nptv6_14 -- /48 internal, /64 external.  Bits in the inside source address
 * corresponding with the non-overlapping bits of the two prefixes are zero.
 * If any of these bets was non-zero, then the translation would fail.
 *
 *                        internal         external
 *                                  +-----+
 * host1       fd01:203:405::1/48   |     | 2001:db8:1::1/64            host2
 * .2   ----------------------------| uut |---------------------------- .2
 *                           dp1T0  |     | dp2T1
 *                                  +-----+
 *
 */
DP_DECL_TEST_CASE(npf_nptv6, nptv6_14, NULL, NULL);
DP_START_TEST(nptv6_14, test)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;
	struct rte_mbuf *exp_pak;

	/*
	 * Setup interfaces
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "10.10.1.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "10.10.2.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "fd01:203:405::1/48");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:db8:1::1/64");

	dp_test_netlink_add_neigh("dp1T0", "fd01:203:405::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp1T1", "2001:db8:1::2",
				  "aa:bb:cc:dd:2:b1");

	/* Config nptv6 */
	dp_test_npf_add_nptv6("dp1T1", 10,
			      "fd01:203:405::/48",
			      "2001:db8:1::/64", true);

	struct dp_test_pkt_desc_t pkt1_pre = {
		.text       = "Internal to external, pre",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "FD01:203:405::2",  /* <--- Orig */
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2001:DB8:1::2",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 49152,
				.dport = 80
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T1"
	};

	struct dp_test_pkt_desc_t pkt1_post = {
		.text       = "Internal to external, post",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:DB8:1:0:d54f::2",  /* <--- Translated */
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2001:DB8:1::2",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 49152,
				.dport = 80
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T1"
	};

	struct dp_test_pkt_desc_t pkt2_pre = {
		.text       = "External to internal, pre",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:DB8:1::2",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "2001:DB8:1:0:d54f::2",  /* Before nptv6 */
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 80,
				.dport = 49152
			}
		},
		.rx_intf    = "dp1T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t pkt2_post = {
		.text       = "External to internal, post",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:DB8:1::2",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "FD01:203:405::2",  /* After nptv6 */
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 80,
				.dport = 49152
			}
		},
		.rx_intf    = "dp1T1",
		.tx_intf    = "dp1T0"
	};

	char intl_intf[IFNAMSIZ];
	char extl_intf[IFNAMSIZ];

	dp_test_intf_real(pkt1_pre.rx_intf, intl_intf);
	dp_test_intf_real(pkt1_pre.tx_intf, extl_intf);

	/*****************************************************************
	 * Internal to external
	 *****************************************************************/

	test_pak = dp_test_v6_pkt_from_desc(&pkt1_pre);

	exp_pak = dp_test_v6_pkt_from_desc(&pkt1_post);
	test_exp = dp_test_exp_from_desc(exp_pak, &pkt1_pre);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", test_exp);


	/*****************************************************************
	 * External to internal
	 *****************************************************************/

	test_pak = dp_test_v6_pkt_from_desc(&pkt2_pre);

	exp_pak = dp_test_v6_pkt_from_desc(&pkt2_post);
	test_exp = dp_test_exp_from_desc(exp_pak, &pkt2_pre);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T1", test_exp);

	if (0) {
		dp_test_npf_show_rules("nptv6-in");
		dp_test_npf_show_rules("nptv6-out");
	}

	/*
	 * Cleanup
	 */
	dp_test_npf_del_nptv6("dp1T1", 10,
			      "fd01:203:405::/48",
			      "2001:db8:1::/64");

	dp_test_npf_cleanup();
	dp_test_npf_nptv6_cleanup("dp1T1");

	dp_test_netlink_del_neigh("dp1T0", "fd01:203:405::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp1T1", "2001:db8:1::2",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "10.10.1.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "fd01:203:405::1/48");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:db8:1::1/64");

} DP_END_TEST;
