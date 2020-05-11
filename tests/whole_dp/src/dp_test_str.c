/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * String manipulation and conversion routines
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <rte_ether.h>

#include "dp_test_lib_internal.h"
#include "dp_test_str.h"

/*
 * Convert string to IP address and mask.  Returns 1 if successful,
 * 0 if not.
 */
int
dp_test_str2ip(const char *str, in_addr_t *ip_addr, int *mask)
{
	char *sub;
	int rv;

	/* Remove the mask, if present */
	sub = strstr(str, "/");
	if (sub) {
		*mask = atoi(sub+1);
		*sub = '\0';
	} else {
		*mask = 32;
	}

	/* Convert from text to IP address */
	rv = inet_pton(AF_INET, str, ip_addr);

	return rv;
}

/*
 * Convert string to IPv6 address and mask.  Returns 1 if successful,
 * 0 if not.
 */
int
dp_test_str2ip6(const char *str, struct in6_addr *ip6_addr, int *mask)
{
	char *sub;
	int rv;

	/* Remove the mask, if present */
	sub = strstr(str, "/");
	if (sub) {
		*mask = atoi(sub+1);
		*sub = '\0';
	} else {
		*mask = 128;
	}

	/* Convert from text to IPv6 address */
	rv = inet_pton(AF_INET6, str, ip6_addr);

	return rv;
}

/*
 * Convert IPv4 or IPv6 string and prefix length to a network string and
 * prefix, e.g.  "10.1.1.1/24" to "10.1.1.0/24", or "2001:1:1::1/64", to
 * "2001:1:1::/64"
 */
void
dp_test_ipstr_to_netstr(const char *ipstr, char *netstr, size_t netstr_len)
{
	struct dp_test_prefix pfx;
	char str[INET6_ADDRSTRLEN];

	netstr[0] = '\0';

	if (!dp_test_prefix_str_to_prefix(ipstr, &pfx))
		return;

	if (pfx.addr.family == AF_INET) {
		struct in_addr net;

		net.s_addr = dp_test_ipv4_addr_to_network(pfx.addr.addr.ipv4,
							  pfx.len);
		inet_ntop(AF_INET, &net, str, sizeof(str));
	} else {
		struct in6_addr net;

		dp_test_ipv6_addr_to_network(&pfx.addr.addr.ipv6, &net,
					     pfx.len);
		inet_ntop(AF_INET6, &net, str, sizeof(str));
	}
	spush(netstr, netstr_len, "%s/%d", str, pfx.len);
}

/*
 * Convert an IP address string of the form "10.1.1.0/24" to an address range
 * string of the form "10.1.1.1-10.1.1.254".  Returns 1 if successful, 0 if
 * not.
 */
uint
dp_test_ipstr_to_range(const char *ipstr, char *range, uint rlen)
{
	struct in_addr lo, hi;
	in_addr_t subnet, bcast;
	struct dp_test_prefix pfx;

	if (rlen < DP_TEST_IPSTR_TO_RANGE_MIN_LEN ||
	    !dp_test_prefix_str_to_prefix(ipstr, &pfx) ||
	    pfx.len >= DP_TEST_IPSTR_TO_RANGE_MIN_LEN)
		return 0;

	/* Ensure no hosts bits are set */
	subnet = dp_test_ipv4_addr_to_network(pfx.addr.addr.ipv4, pfx.len);

	bcast = dp_test_ipv4_addr_to_bcast(pfx.addr.addr.ipv4, pfx.len);

	lo.s_addr = htonl(ntohl(subnet) + 1);
	hi.s_addr = htonl(ntohl(bcast) - 1);

	int l;
	l = spush(range, rlen, "%s-", inet_ntoa(lo));
	l += spush(range + l, rlen - l, "%s", inet_ntoa(hi));

	return 1;
}

/*
 * Convert MAC address to a temporary string
 */
#define MAC_STR_MAX 20
#define N_MAC_STR 4
static char mac_str[N_MAC_STR][MAC_STR_MAX];
static int cur_mac_str;

char *
dp_test_mac2str(struct rte_ether_addr *mac)
{
	char *str = mac_str[cur_mac_str];

	if (++cur_mac_str >= N_MAC_STR)
		cur_mac_str = 0;

	spush(str, MAC_STR_MAX, "%02x:%02x:%02x:%02x:%02x:%02x",
	      mac->addr_bytes[0], mac->addr_bytes[1],
	      mac->addr_bytes[2], mac->addr_bytes[3],
	      mac->addr_bytes[4], mac->addr_bytes[5]);

	return str;
}

/*
 * Take a MAC address string with leading zeros or no leading zeros, and lower
 * or upper case hex digits and convert it to no leading zeros and lowercase.
 * This is typically the MAC address string format returned from the
 * dataplane.
 */
char *
dp_test_canonicalise_macstr(const char *macstr, char *canon)
{
	struct rte_ether_addr mac;

	if (!ether_aton_r(macstr, &mac))
		return NULL;

	return ether_ntoa_r(&mac, canon);
}

/*
 * Insert a string (insert) into another string (haystack) before or after a
 * sub-string (needle).
 *
 * The sub-string should be a string, and not a pointer into haystack. Returns
 * a new string, which the caller must free.
 */
char *
dp_test_str_insert(const char *haystack, const char *needle,
		   const char *insert, bool after)
{
	char *new, *insert_ptr;
	uint insert_pos;

	if (!haystack || !needle || !insert)
		return NULL;

	insert_ptr = strstr(haystack, needle);
	if (!insert_ptr)
		return NULL;

	if (after)
		insert_ptr += strlen(needle);

	new = malloc(strlen(haystack) + strlen(insert) + 1);
	if (!new)
		return NULL;

	/* Pointer to offset */
	insert_pos = insert_ptr - haystack;

	/* Copy string up to the point we are inserting at */
	strncpy(new, haystack, insert_pos);
	new[insert_pos] = '\0';

	/* Insert the string */
	strcat(new, insert);

	/* Copy remaining part of originial string */
	strcat(new, haystack + insert_pos);

	return new;
}

/*
 * Insert a string into another string, before a sub-string.  The sub-string
 * should be a string, and not a pointer into haystack.  Returns a new string,
 * which the caller must free.
 */
char *
dp_test_str_insert_before(const char *haystack, const char *needle,
			  const char *insert)
{
	return dp_test_str_insert(haystack, needle, insert, false);
}

/*
 * Insert a string into another string, after a sub-string.  The sub-string
 * should be a string, and not a pointer into haystack. Returns a new string,
 * which the caller must free.
 */
char *
dp_test_str_insert_after(const char *haystack, const char *needle,
			 const char *insert)
{
	return dp_test_str_insert(haystack, needle, insert, true);
}

/*
 * Count the occurences of needle in haystack (non-overlapping)
 */
static uint
dp_test_str_count(const char *haystack, const char *needle)
{
	size_t needle_len;
	uint count = 0;
	const char *tmp;

	if (!haystack || !needle)
		return 0;

	tmp = haystack;

	needle_len = strlen(needle);
	if (needle_len == 0)
		return 0;

	while ((tmp = strstr(tmp, needle))) {
		tmp += needle_len;
		count++;
	}
	return count;
}

/*
 * Replace all occurences of string 'needle' in string 'haystack'.  Returns a
 * new string, which the caller must free when finished with.
 */
char *
dp_test_str_replace(const char *haystack, const char *needle,
		     const char *replacement)
{
	size_t hays_len, needle_len, repl_len, new_len;
	uint count;
	char *new;

	if (!haystack || !needle || !replacement)
		return NULL;

	/*
	 * Check string lengths, and malloc some memory to hold the new string
	 */
	hays_len = strlen(haystack);
	needle_len = strlen(needle);
	repl_len = strlen(replacement);

	if (!hays_len || !needle_len || !repl_len)
		return NULL;

	count = dp_test_str_count(haystack, needle);
	if (count == 0)
		return NULL;

	/* Add or subtract difference */
	new_len = hays_len - (needle_len - repl_len) * count + 1;

	new = malloc(new_len);
	if (!new)
		return NULL;

	char *insert_point = new;
	const char *tmp = haystack;

	while (true) {
		const char *p = strstr(tmp, needle);

		/* No more occurences, so copy remaining part */
		if (!p) {
			strcpy(insert_point, tmp);
			break;
		}

		/* copy part before needle */
		memcpy(insert_point, tmp, p - tmp);
		insert_point += p - tmp;

		/* copy replacement string */
		memcpy(insert_point, replacement, repl_len);
		insert_point += repl_len;

		/* move pointer in orig string past the needle */
		tmp = p + needle_len;
	}

	return new;
}

/*
 * Split a string into lines.  Returns a pointer to an array of strings, each
 * array element string being a line from the input string.  The size of the
 * array is returned via countp.
 *
 * dp_test_str_split_free should subsequently be called to free the array.
 */
char **
dp_test_str_split(const char *target, int *countp)
{
	char *p, *copy;
	char **result = NULL;
	int count = 0;

	if (!target || !countp)
		return NULL;

	copy = strdup(target);
	p = strtok(copy, "\n");

	while (p != NULL) {
		void *tmp;

		tmp = realloc(result, sizeof(char *) * (count + 1));
		if (!tmp) {
			dp_test_str_split_free(result, count);
			free(copy);
			return NULL;
		}
		result = tmp;

		result[count] = malloc(strlen(p) + 1);
		strcpy(result[count], p);
		count++;
		p = strtok(NULL, "\n");
	}
	free(copy);

	*countp = count;
	return result;
}

/*
 * Free an array of strings previously created by dp_test_str_split
 */
void
dp_test_str_split_free(char **arr, int count)
{
	int i;

	if (!arr)
		return;

	for (i = 0; i < count; ++i)
		if (arr[i])
			free(arr[i]);
	free(arr);
}
