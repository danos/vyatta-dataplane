/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane tests of npf ptree
 */
#include <libmnl/libmnl.h>
#include <linux/random.h>
#include <netinet/in.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"
#include "npf/npf.h"
#include "npf/npf_cache.h"
#include "npf/npf_rule_gen.h"
#include "npf/npf_session.h"
#include "npf/npf_ruleset.h"
#include "npf/npf_ptree.h"
#include "npf/config/npf_config.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_npf_fw_lib.h"

/* Forward reference */
static char *ptree_key2string(uint8_t *key, uint klen, bool isaddr);


/*
 * The ptree holds keys/addresses in network byte order.  This unit test file
 * deals in host byte order to make things more intuitive.  Swap kays where
 * necessary.
 */
static inline void
ptree_key_swap(uint8_t *dest, uint8_t *src, uint8_t len)
{
	uint8_t tmp[16];
	int i;

	if (!src || !dest)
		return;

	if (src == dest) {
		if (len > sizeof(tmp))
			return;

		memcpy(tmp, src, len);
		src = tmp;
	}
	for (i = 0; i < len; i++)
		dest[i] = src[len-i-1];
}

#define LENGTH2MASK32(_b) (0xFFFFFFFF << (32-(_b)))

/*
 * byte swap key and insert into table.  Verify key is added/not added.
 */
static int
_ptree_test_insert(struct ptree_table *tbl, uint8_t *key, uint8_t klen,
		   uint8_t mask, bool exp_pass, const char *file, int line)
{
	int rc;
	uint8_t net_order[16];

	ptree_key_swap(net_order, key, ptree_get_table_keylen(tbl));
	key = net_order;

	rc = ptree_insert(tbl, key, mask);

	if (exp_pass && rc != 0)
		_dp_test_fail(file, line, "Failed to add %s/%u",
			      ptree_key2string(key, klen, true), mask);

	if (!exp_pass && rc == 0)
		_dp_test_fail(file, line, "Did not expect %s/%u to be added",
			      ptree_key2string(key, klen, true), mask);

	return rc;
}
#define ptree_test_insert(_t, _k, _l, _m, _e)				\
	_ptree_test_insert(_t, _k, _l, _m, _e, __FILE__, __LINE__)

/*
 * byte swap key and remove table
 */
static int
ptree_test_remove(struct ptree_table *tbl, uint8_t *key, uint mask)
{
	int rc;
	uint8_t net_order[16];

	ptree_key_swap(net_order, key, ptree_get_table_keylen(tbl));
	key = net_order;

	rc = ptree_remove(tbl, key, mask);
	return rc;
}

/*
 * Short lived static buffers.
 */
#define TEMP_BUF_COUNT 10
#define TEMP_BUF_SIZE  MAX(100, INET6_ADDRSTRLEN)


static char *temp_buf(size_t *len)
{
	static char str[TEMP_BUF_COUNT][TEMP_BUF_SIZE];
	static int cur = -1;

	if (++cur == TEMP_BUF_COUNT)
		cur = 0;
	str[cur][0] = 0;

	if (len)
		*len = TEMP_BUF_SIZE;

	return str[cur];
}

/*
 * Get key from table entry, and return in host byte order.
 */
static uint8_t *ptree_test_get_key(struct ptree_node *n)
{
	uint8_t *key = ptree_get_key(n);
	size_t len;

	if (!key)
		return NULL;

	uint8_t *buf = (uint8_t *)temp_buf(&len);

	ptree_key_swap(buf, key, ptree_get_keylen(n));

	return buf;
}

/*
 * byte swap key and do a shortest match lookup
 */
static struct ptree_node *
ptree_test_shortest_match(struct ptree_table *tbl, uint8_t *key)
{
	struct ptree_node *pn;
	uint8_t net_order[16];

	ptree_key_swap(net_order, key, ptree_get_table_keylen(tbl));
	key = net_order;

	pn = ptree_shortest_match(tbl, key);
	return pn;
}

/*
 * Lookup key1 shortest match, expect to find key2
 */
static void
_ptree_verify_shortest_match(struct ptree_table *tbl, uint8_t *key1,
			     uint8_t klen, uint8_t *key2,
			     const char *file, int line)
{
	struct ptree_node *pn;
	uint8_t *k;

	pn = ptree_test_shortest_match(tbl, key1);

	_dp_test_fail_unless(pn, file, line,
			     "Failed to find shortest match for %s",
			     ptree_key2string(key1, klen, true));

	k = ptree_test_get_key(pn);
	_dp_test_fail_unless(!memcmp(key2, k, klen),
			     file, line,
			     "Expected %s, found %s",
			     ptree_key2string(key2, klen, true),
			     ptree_key2string(k, klen, true));
}
#define ptree_verify_shortest_match(_t, _k, _l, _e)			\
	_ptree_verify_shortest_match(_t, _k, _l, _e, __FILE__, __LINE__)

/*
 * byte swap key and do a longest match lookup
 */
static struct ptree_node *
ptree_test_longest_match(struct ptree_table *tbl, uint8_t *key)
{
	struct ptree_node *pn;
	uint8_t net_order[16];

	ptree_key_swap(net_order, key, ptree_get_table_keylen(tbl));
	key = net_order;

	pn = ptree_longest_match(tbl, key);
	return pn;
}

/*
 * Lookup key1 longest match, expect to find key2
 */
static void
_ptree_verify_longest_match(struct ptree_table *tbl, uint8_t *key1,
			     uint8_t klen, uint8_t *key2,
			     const char *file, int line)
{
	struct ptree_node *pn;
	uint8_t *k;

	pn = ptree_test_longest_match(tbl, key1);

	_dp_test_fail_unless(pn, file, line,
			     "Failed to find longest match for %s",
			     ptree_key2string(key1, klen, true));

	k = ptree_test_get_key(pn);
	_dp_test_fail_unless(!memcmp(key2, k, klen),
			     file, line,
			     "Expected %s, found %s",
			     ptree_key2string(key2, klen, true),
			     ptree_key2string(k, klen, true));
}
#define ptree_verify_longest_match(_t, _k, _l, _e)			\
	_ptree_verify_longest_match(_t, _k, _l, _e, __FILE__, __LINE__)


/*
 *
 */
static void
_ptree_verify_key(uint8_t *key, uint8_t klen, uint8_t *exp,
		  const char *file, int line)
{
	if (memcmp(key, exp, klen) != 0)
		_dp_test_fail(file, line,
			      "Expected %s, found %s",
			      ptree_key2string(exp, klen, false),
			      ptree_key2string(key, klen, false));
}
#define ptree_verify_key(_k, _l, _e)			\
	_ptree_verify_key(_k, _l, _e, __FILE__, __LINE__)

/*
 * Parse a string of format "10.0.0.1", "10.0.2.0/24", "2001::2", or
 * "2001::0/64", and write to a byte array 'key'.  Returns key length > 0 if
 * successful.
 */
static int
ptree_string2key(const char *string, uint8_t *key, uint8_t *af,
		 uint8_t *mask)
{
	char s[80];
	uint8_t tmp[16];

	snprintf(s, sizeof(s), "%s", string);

	if (strchr(s, '.')) {
		*af = AF_INET;
		*mask = 32;
	} else if (strchr(s, ':')) {
		*af = AF_INET6;
		*mask = 128;
	} else {
		printf("Not IP or IPv6\n");
		return 0;
	}
	char *slash = strchr(s, '/');
	int rc;

	if (slash) {
		char *mask_str;
		char *endp;
		ulong len;

		*slash = '\0';
		mask_str = slash + 1;
		len = strtoul(mask_str, &endp, 10);
		if (endp == mask_str || len > *mask) {
			printf("strtoul failed\n");
			return 0;
		}
		*mask = len;
	}

	rc = inet_pton(*af, s, tmp);
	ptree_key_swap(key, tmp, AF_INET ? 4 : 16);

	/* Restore slash */
	if (slash)
		*slash = '/';

	if (rc != 1)
		return 0;

	return (*af == AF_INET) ? 4 : 16;
}

/*
 * Return a string representation of a byte array, either as an IPv4/IPv6
 * address or a hex string.
 *
 * To return an address string, isaddr should be set true and klen should be 4
 * or 16.
 */
static char *
ptree_key2string(uint8_t *key, uint klen, bool isaddr)
{
	size_t slen;
	char *str = temp_buf(&slen);
	int i, l = 0;

	str[0] = '\0';

	if (!isaddr || (klen != 4 && klen != 16)) {
		/*
		 * Return hex byte string, most-significant on left
		 */
		l += snprintf(str+l, slen-l, "0x");
		for (i = klen - 1; i >= 0; i--)
			l += snprintf(str+l, slen-l, "%02X", key[i]);
		return str;
	}

	if (klen == 4) {
		uint32_t addr4 = htonl(*(uint32_t *)key);

		inet_ntop(AF_INET, &addr4, str, slen);
	} else if (klen == 16) {
		inet_ntop(AF_INET6, key, str, slen);
	}
	return str;
}

/*
 * Simple handler for generic walk function.  Just counts leaves.
 */
static pt_walk_cb npf_ptree_walk_handler;

static int npf_ptree_walk_handler(struct ptree_node *n, void *data)
{
	uint32_t *count = data;

	*count += 1;
	return 0;
}


DP_DECL_TEST_SUITE(npf_ptree);

DP_DECL_TEST_CASE(npf_ptree, npf_ptree_case1, NULL, NULL);

/*
 * Test adding and deleting entries just below root.  This is subtely
 * different from deeper table adds, as the root branch node is the only
 * branch node that can ever have NULL pointers.
 */
DP_START_TEST(npf_ptree_case1, test1)
{
	struct ptree_table *tbl;
	uint8_t key1[16], key2[16];
	uint8_t klen = 4;
	uint8_t af, mask;
	uint count;
	int rc;

	tbl = ptree_table_create(klen);
	dp_test_fail_unless(tbl, "Failed to create IPv4 ptree table");

	/*
	 * Insert key 127.0.0.1 (on left of root, since ms bit is 0)
	 */
	klen = ptree_string2key("127.0.0.1", key1, &af, &mask);
	if (!klen || af != AF_INET || mask != 32)
		dp_test_fail("klen %d af %u, mask %u", klen, af, mask);

	/* Insert key */
	ptree_test_insert(tbl, key1, klen, mask, true);

	/* Lookup longest match */
	ptree_verify_longest_match(tbl, key1, klen, key1);

	/* Lookup shortest match */
	ptree_verify_shortest_match(tbl, key1, klen, key1);

	/* Generic walk */
	count = 0;
	ptree_walk(tbl, PT_UP, npf_ptree_walk_handler, &count);
	dp_test_fail_unless(count == 1,
			    "Expected 1 leaves, walk found %u", count);

	/* Remove key */
	rc = ptree_test_remove(tbl, key1, mask);
	dp_test_fail_unless(!rc, "Failed to remove %s",
			    ptree_key2string(key1, klen, true));


	/*
	 * Insert key 128.0.0.1 (on right of root, since ms bit is 1)
	 */
	klen = ptree_string2key("128.0.0.1", key1, &af, &mask);
	if (!klen || af != AF_INET || mask != 32)
		dp_test_fail("klen %d af %u, mask %u", klen, af, mask);

	/* Insert key */
	ptree_test_insert(tbl, key1, klen, mask, true);

	/* Lookup longest match */
	ptree_verify_longest_match(tbl, key1, klen, key1);

	/* Lookup shortest match */
	ptree_verify_shortest_match(tbl, key1, klen, key1);

	/* Generic walk */
	count = 0;
	ptree_walk(tbl, PT_UP, npf_ptree_walk_handler, &count);
	dp_test_fail_unless(count == 1,
			    "Expected 1 leaves, walk found %u", count);

	/* Remove key */
	rc = ptree_test_remove(tbl, key1, mask);
	dp_test_fail_unless(!rc, "Failed to remove %s",
			    ptree_key2string(key1, klen, true));


	/*
	 * Insert keys 127.0.0.1 and 63.0.0.1
	 */
	klen = ptree_string2key("127.0.0.1", key1, &af, &mask);
	if (!klen || af != AF_INET || mask != 32)
		dp_test_fail("klen %d af %u, mask %u", klen, af, mask);

	/* Insert key1 */
	ptree_test_insert(tbl, key1, klen, mask, true);

	klen = ptree_string2key("63.0.0.1", key2, &af, &mask);
	if (!klen || af != AF_INET || mask != 32)
		dp_test_fail("klen %d af %u, mask %u", klen, af, mask);

	/* Insert key2 */
	ptree_test_insert(tbl, key2, klen, mask, true);

	/* Lookup key1 longest match */
	ptree_verify_longest_match(tbl, key1, klen, key1);

	/* Lookup key2 longest match */
	ptree_verify_longest_match(tbl, key2, klen, key2);

	/* Generic walk */
	count = 0;
	ptree_walk(tbl, PT_UP, npf_ptree_walk_handler, &count);
	dp_test_fail_unless(count == 2,
			    "Expected 2 leaves, walk found %u", count);

	/* Remove key1 */
	rc = ptree_test_remove(tbl, key1, mask);
	dp_test_fail_unless(!rc, "Failed to remove %s",
			    ptree_key2string(key1, klen, true));

	/* Lookup key2 longest match */
	ptree_verify_longest_match(tbl, key2, klen, key2);

	/*
	 * Insert keys 128.0.0.1 and 192.0.0.1
	 */
	klen = ptree_string2key("128.0.0.1", key1, &af, &mask);
	if (!klen || af != AF_INET || mask != 32)
		dp_test_fail("klen %d af %u, mask %u", klen, af, mask);

	/* Insert key1 */
	ptree_test_insert(tbl, key1, klen, mask, true);

	klen = ptree_string2key("192.0.0.1", key2, &af, &mask);
	if (!klen || af != AF_INET || mask != 32)
		dp_test_fail("klen %d af %u, mask %u", klen, af, mask);

	/* Insert key2 */
	ptree_test_insert(tbl, key2, klen, mask, true);

	/* Lookup key2 longest match */
	ptree_verify_longest_match(tbl, key2, klen, key2);

	/* Generic walk */
	count = 0;
	ptree_walk(tbl, PT_UP, npf_ptree_walk_handler, &count);
	dp_test_fail_unless(count == 3,
			    "Expected 3 leaves, walk found %u", count);

	/* Remove key1 */
	rc = ptree_test_remove(tbl, key1, mask);
	dp_test_fail_unless(!rc, "Failed to remove %s",
			    ptree_key2string(key1, klen, true));


	/* Lookup key2 longest match */
	ptree_verify_longest_match(tbl, key2, klen, key2);

	/*
	 * Destroy table with 2 entries
	 */
	rc = ptree_table_destroy(tbl);
	dp_test_fail_unless(!rc, "Failed to destroy IPv4 ptree table");

} DP_END_TEST;

static pt_ipv4_range_cb npf_ptree_range_walk_handler;

static int npf_ptree_range_walk_handler(struct ptree_ipv4_range_ctx *ctx)
{
	uint32_t *count = (uint32_t *)(ctx->data);
	uint32_t addr = 0, mask;

	*count += 1;

	if (*count == 5) {
		/* Leaf E */
		addr = 0x80;
		mask = 0xFFFFFFFC;

		dp_test_fail_unless(ctx->addr_naddrs == 2,
				    "%u Num addrs %u, expected 1",
				    *count, ctx->addr_naddrs);
		dp_test_fail_unless(ctx->addr_first == addr + 1,
				    "%u First addr 0x%08X, expected 0x%08X",
				    *count, ctx->addr_first, addr + 1);
		dp_test_fail_unless(ctx->addr_last == addr + 2,
				    "%u Last addr 0x%08X, expected 0x%08X",
				    *count, ctx->addr_last, addr + 2);
		dp_test_fail_unless(ctx->addr_mask == mask,
				    "%u Mask 0x%08X, expected 0x%08X",
				    *count, ctx->addr_mask, mask);
		return 0;
	}

	mask = 0xFFFFFFFF;

	switch (*count) {
	case 1:
		addr = 0xC;
		break;
	case 2:
		addr = 0x20;
		break;
	case 3:
		addr = 0x40;
		break;
	case 4:
		addr = 0x44;
		break;
	case 6:
		addr = 0x82;
		break;
	case 7:
		addr = 0x88;
		break;
	case 8:
		addr = 0xA0;
		break;
	default:
		dp_test_fail("Unexpected count %u", *count);
	}

	dp_test_fail_unless(ctx->addr_naddrs == 1,
			    "%u Num addrs %u, expected 1",
			    *count, ctx->addr_naddrs);
	dp_test_fail_unless(ctx->addr_first == addr,
			    "%u First addr 0x%08X, expected 0x%08X",
			    *count, ctx->addr_first, addr);
	dp_test_fail_unless(ctx->addr_last == addr,
			    "%u Last addr 0x%08X, expected 0x%08X",
			    *count, ctx->addr_last, addr);
	dp_test_fail_unless(ctx->addr_mask == mask,
			    "%u Mask 0x%08X, expected 0x%08X",
			    *count, ctx->addr_mask, mask);

	return 0;
}

DP_DECL_TEST_CASE(npf_ptree, npf_ptree_case2, NULL, NULL);

/*
 * Tests the following tree.  Specifically, it tests all combinations
 * under node [f,4], i.e. 0x00000080 to 0x0000009F ... last byte
 * 100* ****
 *
 *                                    [a,0]
 *                           0****    /   \   1****
 *                                   /     \
 *                    +-------------+       +------------------+
 *                   /                                          \
 *                  /                                            \
 *               [c,1]                                          [g,2]
 *          00 /       \ 01                                   /       \
 *            /         \                               1*0  /         \ 1*1
 *           /           \                                  /           \
 *        [b,2]           \                              [f,4]         0xA0/32
 *   000  /   \001         \                     1*0*0   /   \ 1*0*1   H
 *       /     \            \                           /     \
 *      /       \            \                         /      0x88/32
 *   0x0C/32   0x20/32      [d,5]                    [e,6]    G
 *   A         B           /	  \                 /     \
 *                 01***0 /  01***1\       1*0*0*0 /       \ 1*0*0*1
 *                       /          \             /         \
 *                     0x40/32     0x44/32     0x80/30    0x82/32
 *                     C           D            E         F
 *
 */
DP_START_TEST(npf_ptree_case2, test1)
{
	struct ptree_table *tbl;
	uint8_t key1[16];
	uint8_t klen = 4;
	uint8_t af, mask;
	uint32_t addr;
	int rc;
	uint i;

	tbl = ptree_table_create(klen);
	dp_test_fail_unless(tbl, "Failed to create IPv4 ptree table");

	/*
	 * This creates the example tree shown at the top of npf_ptree.c
	 */
	static const char * const data[] = {
		"0.0.0.12/32",   /* A 0x0C */
		"0.0.0.32/32",   /* B 0x20 */
		"0.0.0.64/32",   /* C 0x40 */
		"0.0.0.68/32",   /* D 0x44 */
		"0.0.0.128/30",  /* E 0x80 */
		"0.0.0.130/32",  /* F 0x82  */
		"0.0.0.136/32",  /* G 0x88  */
		"0.0.0.160/32",  /* H 0xA0 */
	};

	for (i = 0; i < ARRAY_SIZE(data); i++) {

		klen = ptree_string2key(data[i], key1, &af, &mask);
		if (!klen || af != AF_INET)
			dp_test_fail("klen %d af %u, mask %u", klen, af, mask);

		/* Insert key */
		ptree_test_insert(tbl, key1, klen, mask, true);

		/* Lookup longest match */
		ptree_verify_longest_match(tbl, key1, klen, key1);
	}

	/*
	 * Test all variations of least-significant byte 100*****, i.e.
	 * everything below node [f,4]
	 */
	uint8_t smk[4], lmk[4], Ek[4];

	for (addr = 0x80; addr <= 0x9F; addr++) {
		struct ptree_node *lm, *sm;
		uint8_t *key = (uint8_t *)&addr;

		sm = ptree_test_shortest_match(tbl, key);
		lm = ptree_test_longest_match(tbl, key);

		if (sm)
			ptree_key_swap(smk, ptree_get_key(sm), klen);
		if (lm)
			ptree_key_swap(lmk, ptree_get_key(lm), klen);

		switch (addr) {
		case 0x80: /* E */
			/* Verify shortest match matches leaf E */
			dp_test_fail_unless(sm,
					    "Failed shortest match for 0x%08X",
					    addr);
			ptree_verify_key(smk, klen, key);

			/* Verify longest match matches leaf E */
			dp_test_fail_unless(lm,
					    "Failed longest match for  0x%08X",
					    addr);
			ptree_verify_key(lmk, klen, key);
			memcpy(Ek, lmk, 4);
			break;

		case 0x81:
			/* Verify shortest match matches leaf E */
			dp_test_fail_unless(sm,
					    "Failed shortest match for 0x%08X",
					    addr);
			ptree_verify_key(smk, klen, Ek);

			/* Verify longest match matches leaf E */
			dp_test_fail_unless(lm,
					    "Failed longest match for  0x%08X",
					    addr);
			ptree_verify_key(lmk, klen, Ek);
			break;

		case 0x82: /* F */
			/* Verify shortest match matches leaf E */
			dp_test_fail_unless(sm,
					    "Failed shortest match for 0x%08X",
					    addr);
			ptree_verify_key(smk, klen, Ek);

			/* Verify longest match matches leaf F */
			dp_test_fail_unless(lm,
					    "Failed longest match for  0x%08X",
					    addr);
			ptree_verify_key(lmk, klen, key);
			break;

		case 0x83:
			/* Verify shortest match matches leaf E */
			dp_test_fail_unless(sm,
					    "Failed shortest match for 0x%08X",
					    addr);
			ptree_verify_key(smk, klen, Ek);

			/* Verify longest match matches leaf E */
			dp_test_fail_unless(lm,
					    "Failed longest match for  0x%08X",
					    addr);
			ptree_verify_key(lmk, klen, Ek);
			break;

		case 0x88: /* G */
			/* Verify shortest match matches leaf G */
			dp_test_fail_unless(sm,
					    "Failed shortest match for 0x%08X",
					    addr);
			ptree_verify_key(smk, klen, key);

			/* Verify longest match matches leaf G */
			dp_test_fail_unless(lm,
					    "Failed longest match for  0x%08X",
					    addr);
			ptree_verify_key(lmk, klen, key);
			break;

		default:
			dp_test_fail_unless(!sm,
					    "Looked up shortest match for "
					    "0x%08X, found %s", addr,
					    ptree_key2string(smk, klen, false));
			dp_test_fail_unless(!lm,
					    "Looked up longest match for "
					    "0x%08X, found %s", addr,
					    ptree_key2string(lmk, klen, false));
			break;
		}
	}

	/*
	 * Test walk functions
	 */
	struct ptree_ipv4_range_ctx *range_ctx;
	uint count = 0;
	uint *countp;

	/* Generic walk */
	ptree_walk(tbl, PT_UP, npf_ptree_walk_handler, &count);
	dp_test_fail_unless(count == 8,
			    "Expected 8 leaves, walk found %u", count);

	/* Range walk */
	range_ctx = calloc(1, sizeof(*range_ctx) + sizeof(uint32_t));
	assert(range_ctx);
	countp = (uint32_t *)(range_ctx->data);

	ptree_ipv4_addr_range_walk(tbl, npf_ptree_range_walk_handler,
				   range_ctx);
	dp_test_fail_unless(*countp == 8,
			    "Expected 8 leaves, walk found %u", *countp);

	/* Sum of all useable addresses in table */
	uint64_t total;

	total = ptree_ipv4_table_range(tbl);
	dp_test_fail_unless(total == 9lu,
			    "Expected 9 useable addrs, walk found %lu", total);

	free(range_ctx);

	/*
	 * Destroy table
	 */
	rc = ptree_table_destroy(tbl);
	dp_test_fail_unless(!rc, "Failed to destroy IPv4 ptree table");

} DP_END_TEST;



DP_DECL_TEST_CASE(npf_ptree, npf_ptree_case3, NULL, NULL);

/*
 * IPv4
 */
DP_START_TEST(npf_ptree_case3, test1)
{
	struct ptree_table *tbl;
	struct ptree_node *pn;
	uint8_t key1[16], key2[16];
	uint8_t klen = 4;
	uint8_t af, mask;
	int rc;
	uint count, i;

	tbl = ptree_table_create(klen);
	dp_test_fail_unless(tbl, "Failed to create IPv4 ptree table");

	/*
	 * Marriot Blueice address group
	 */
	static const char * const data[] = {
		"32.97.110.58/32",
		"32.97.110.59/32",
		"32.97.110.61/32",
		"32.97.110.62/32",
		"32.97.110.63/32",
		"32.97.110.64/32",
		"32.97.110.65/32",
		"32.97.110.50/32",
		"32.97.110.51/32",
		"32.97.110.52/32",
		"32.97.110.53/32",
		"32.97.110.54/32",
		"32.97.110.55/32",
		"32.97.110.56/32",
		"32.97.110.57/32",
		"129.42.208.179/32",
		"129.42.208.182/32",
		"129.42.208.183/32",
		"129.42.208.184/32",
		"129.42.208.185/32",
		"129.42.208.186/32",
		"129.42.208.187/32",
		"129.42.208.188/32",
		"129.42.208.167/32",
		"129.42.208.169/32",
		"129.42.208.172/32",
		"129.42.208.173/32",
		"129.42.208.174/32",
		"129.42.208.176/32",
		"129.42.208.177/32",
		"129.42.208.178/32",
		"129.42.160.0/20",
		"129.42.161.0/24",
		"61.95.167.0/25",
		"125.18.17.0/24",
		"202.108.130.128/25",
		"220.248.0.128/27",
		"202.74.105.96/27",
		"219.83.65.64/26",
		"211.109.178.0/25",
		"202.162.29.0/26",
		"203.163.71.192/27",
		"202.81.30.0/24",
		"203.113.176.0/24",
		"203.143.159.0/25",
		"203.196.98.0/25",
		"61.90.164.0/27",
		"202.81.18.0/27",
		"203.141.92.0/27",
		"122.248.161.0/24",
		"122.248.162.0/24",
		"122.248.163.0/24",
		"122.248.183.0/24",
		"122.248.182.0/24",
		"32.104.18.0/24",
		"32.59.181.0/28",
		"32.59.1.224/28",
		"32.59.160.32/29",
		"32.59.128.192/27",
		"32.59.160.96/27",
		"32.59.146.192/26",
		"32.59.96.96/27",
		"32.59.64.128/26",
		"32.59.64.192/26",
		"195.212.29.0/24",
		"199.66.29.254/31",
		"199.66.29.255/32",
	};

	for (i = 0; i < ARRAY_SIZE(data); i++) {

		klen = ptree_string2key(data[i], key1, &af, &mask);
		if (!klen || af != AF_INET)
			dp_test_fail("klen %d af %u, mask %u", klen, af, mask);

		/* Insert key */
		ptree_test_insert(tbl, key1, klen, mask, true);

		/* Lookup longest match */
		ptree_verify_longest_match(tbl, key1, klen, key1);
	}

	/* Generic walk */
	count = 0;
	ptree_walk(tbl, PT_UP, npf_ptree_walk_handler, &count);
	dp_test_fail_unless(count == ARRAY_SIZE(data),
			    "Expected %lu leaves, walk found %u",
			    ARRAY_SIZE(data), count);

	/*
	 * Longest  match for 129.42.161.1 is 129.42.161.0/24,
	 * shortest match for 129.42.161.1 is 129.42.160.0/20
	 */
	klen = ptree_string2key("129.42.161.1", key1, &af, &mask);
	(void)ptree_string2key("129.42.161.0", key2, &af, &mask);

	/* Lookup longest match */
	ptree_verify_longest_match(tbl, key1, klen, key2);

	klen = ptree_string2key("129.42.160.0", key2, &af, &mask);
	if (!klen || af != AF_INET)
		dp_test_fail("klen %d af %u, mask %u", klen, af, mask);

	/* Lookup shortest match */
	ptree_verify_shortest_match(tbl, key1, klen, key2);


	/*
	 * Longest  match for 199.66.29.255 is 199.66.29.255/32,
	 * shortest match for 199.66.29.255 is 199.66.29.254/31
	 */
	klen = ptree_string2key("199.66.29.255", key1, &af, &mask);
	(void)ptree_string2key("199.66.29.255", key2, &af, &mask);

	/* Lookup longest match */
	ptree_verify_longest_match(tbl, key1, klen, key2);

	klen = ptree_string2key("199.66.29.254", key2, &af, &mask);
	if (!klen || af != AF_INET)
		dp_test_fail("klen %d af %u, mask %u", klen, af, mask);

	/* Lookup shortest match */
	ptree_verify_shortest_match(tbl, key1, klen, key2);


	/*
	 * Verify a duplicate key (with different mask) cannot be added
	 */
	klen = ptree_string2key("129.42.160.0/24", key1, &af, &mask);

	ptree_test_insert(tbl, key1, klen, mask, false);

	/*
	 * Lookup an address tht is *not* in the table
	 */
	klen = ptree_string2key("32.97.110.20", key1, &af, &mask);

	/* Lookup shortest match */
	pn = ptree_test_shortest_match(tbl, key1);
	dp_test_fail_unless(pn == NULL, "Found a match for %s",
			    ptree_key2string(key1, klen, true));

	/*
	 * Test accessor functions
	 */
	klen = ptree_string2key("203.113.176.0", key1, &af, &mask);
	pn = ptree_test_longest_match(tbl, key1);
	dp_test_fail_unless(pn, "Failed to find longest match for %s",
			    ptree_key2string(key1, klen, true));
	dp_test_fail_unless(ptree_get_keylen(pn) == 4, "Wrong key length");
	dp_test_fail_unless(ptree_get_mask(pn) == 24, "Wrong mask");

	dp_test_fail_unless(ptree_get_table_keylen(tbl) == 4,
			    "Table key length");

	uint32_t leaf_count = ptree_get_table_leaf_count(tbl);
	uint32_t branch_count = ptree_get_table_branch_count(tbl);

	dp_test_fail_unless(leaf_count == 67,
			    "Table leaf count %u, expected 67", leaf_count);
	dp_test_fail_unless(branch_count == 66,
			    "Table branch count %u, expected 66", branch_count);

	uint64_t naddrs = ptree_ipv4_table_range(tbl);
	dp_test_fail_unless(naddrs == 8166,
			    "Number of addresses %lu, expected 8166", naddrs);

	/*
	 * Destroy table
	 */
	rc = ptree_table_destroy(tbl);
	dp_test_fail_unless(!rc, "Failed to destroy IPv4 ptree table");

} DP_END_TEST;


DP_DECL_TEST_CASE(npf_ptree, npf_ptree_case4, NULL, NULL);

/*
 * IPv6
 */
DP_START_TEST(npf_ptree_case4, test1)
{
	struct ptree_table *tbl;
	uint8_t key1[16];
	uint8_t klen = 16;
	uint8_t af, mask;
	int rc;
	uint i;

	tbl = ptree_table_create(klen);
	dp_test_fail_unless(tbl, "Failed to create IPv6 ptree table");

	/*
	 * Use the same address array for IPv6 by using this as the least
	 * significant word in the IPv6 address.
	 */
	static const char * const data[] = {
		"32.97.110.58/32",
		"32.97.110.59/32",
		"32.97.110.61/32",
		"32.97.110.62/32",
		"32.97.110.63/32",
		"32.97.110.64/32",
		"32.97.110.65/32",
		"32.97.110.50/32",
		"32.97.110.51/32",
		"32.97.110.52/32",
		"32.97.110.53/32",
		"32.97.110.54/32",
		"32.97.110.55/32",
		"32.97.110.56/32",
		"32.97.110.57/32",
		"129.42.208.179/32",
		"129.42.208.182/32",
		"129.42.208.183/32",
		"129.42.208.184/32",
		"129.42.208.185/32",
		"129.42.208.186/32",
		"129.42.208.187/32",
		"129.42.208.188/32",
		"129.42.208.167/32",
		"129.42.208.169/32",
		"129.42.208.172/32",
		"129.42.208.173/32",
		"129.42.208.174/32",
		"129.42.208.176/32",
		"129.42.208.177/32",
		"129.42.208.178/32",
		"129.42.160.0/20",
		"129.42.161.0/24",
		"61.95.167.0/25",
		"125.18.17.0/24",
		"202.108.130.128/25",
		"220.248.0.128/27",
		"202.74.105.96/27",
		"219.83.65.64/26",
		"211.109.178.0/25",
		"202.162.29.0/26",
		"203.163.71.192/27",
		"202.81.30.0/24",
		"203.113.176.0/24",
		"203.143.159.0/25",
		"203.196.98.0/25",
		"61.90.164.0/27",
		"202.81.18.0/27",
		"203.141.92.0/27",
		"122.248.161.0/24",
		"122.248.162.0/24",
		"122.248.163.0/24",
		"122.248.183.0/24",
		"122.248.182.0/24",
		"32.104.18.0/24",
		"32.59.181.0/28",
		"32.59.1.224/28",
		"32.59.160.32/29",
		"32.59.128.192/27",
		"32.59.160.96/27",
		"32.59.146.192/26",
		"32.59.96.96/27",
		"32.59.64.128/26",
		"32.59.64.192/26",
		"195.212.29.0/24",
	};

	for (i = 0; i < ARRAY_SIZE(data); i++) {

		memset(key1, 0, klen);

		klen = ptree_string2key(data[i], key1, &af, &mask);
		if (!klen || af != AF_INET)
			dp_test_fail("klen %d af %u, mask %u", klen, af, mask);

		/* to v6 */
		mask += 96;

		/* Insert key */
		ptree_test_insert(tbl, key1, klen, mask, true);

		/* Lookup longest match */
		ptree_verify_longest_match(tbl, key1, klen, key1);
	}

	/*
	 * Destroy table
	 */
	rc = ptree_table_destroy(tbl);
	dp_test_fail_unless(!rc, "Failed to destroy IPv6 ptree table");

} DP_END_TEST;


