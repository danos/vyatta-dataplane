/*-
 * Copyright (c) 2018-2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * String manipulation and conversion routines
 */

#ifndef _DP_TEST_STR_H_
#define _DP_TEST_STR_H_

/*
 * Convert IPv4 or IPv6 string and prefix length to a network string and
 * prefix, e.g.  "10.1.1.1/24" to "10.1.1.0/24", or "2001:1:1::1/64", to
 * "2001:1:1::/64"
 */
void
dp_test_ipstr_to_netstr(const char *ipstr, char *netstr, size_t netstr_len);

/*
 * Convert an IP address string of the form "10.1.1.0/24" to an address range
 * string of the form "10.1.1.1-10.1.1.254".  Returns 1 if successful, 0 if
 * not.
 *
 * rlen must be at least DP_TEST_IPSTR_TO_RANGE_MIN_LEN
 */
#define DP_TEST_IPSTR_TO_RANGE_MIN_LEN 32
uint
dp_test_ipstr_to_range(const char *ipstr, char *range, uint rlen);

/*
 * Insert a string (insert) into another string (haystack) before or after a
 * sub-string (needle).
 *
 * The sub-string should be a string, and not a pointer into haystack. Returns
 * a new string, which the caller must free.
 */
char *
dp_test_str_insert(const char *haystack, const char *needle,
		   const char *insert, bool after);

/*
 * Insert a string (insert) into another string (haystack) after a sub-string
 * (needle).
 *
 * The sub-string should be a string, and not a pointer into haystack. Returns
 * a new string, which the caller must free.
 */
char *
dp_test_str_insert_after(const char *haystack, const char *needle,
			 const char *insert);

/*
 * Replace all occurences of string 'needle' in string 'haystack'.  Returns a
 * new string, which the caller must free when finished with.
 */
char *
dp_test_str_replace(const char *haystack, const char *needle,
		    const char *replacement);

/*
 * Split a string into lines.  Returns a pointer to an array of strings, each
 * array element string being a line from the input string.  The size of the
 * array is returned via countp.
 *
 * dp_test_str_split_free should subsequently be called to free the array.
 */
char **
dp_test_str_split(const char *target, int *countp);

/*
 * Free an array of strings previously created by dp_test_str_split
 */
void
dp_test_str_split_free(char **arr, int count);

#endif
