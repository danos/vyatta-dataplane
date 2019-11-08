/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * IPv6 Network Prefix Translation rproc extension.
 *
 * As per https://tools.ietf.org/html/rfc6296
 */

#include <errno.h>
#include <limits.h>
#include <rte_atomic.h>
#include <rte_spinlock.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <urcu/list.h>
#include "ether.h"
#include "netinet6/in6_var.h"
#include "netinet6/ip6_funcs.h"
#include "netinet6/in6.h"
#include "util.h"

#include "compiler.h"
#include "json_writer.h"
#include "npf/npf.h"
#include "npf/npf_cache.h"
#include "npf/config/npf_config.h"
#include "npf/npf_cmd.h"
#include "npf/npf_ruleset.h"
#include "npf/npf_rule_gen.h"
#include "npf/rproc/npf_rproc.h"
#include "npf/rproc/npf_ext_nptv6.h"

/*
 * Absolute min and max prefix lengths.  A greater MIN or lesser MAX may be
 * enforced by the configuration.
 */
#define NPTV6_PREFIXLEN_MIN 16
#define NPTV6_PREFIXLEN_MAX 112

/* Per-core stats */
struct nptv6_stats {
	uint64_t	ns_drops;
};
#define nptv6_drops_inc(_np) ((_np)->np_stats[dp_lcore_id()].ns_drops++)

/*
 * NPTv6 structure.  One per rule.  There will usually be two rules per
 * translator - one for input and one for output on the same interface.
 */
struct nptv6 {
	/* Pointer back to rule */
	npf_rule_t	*np_rl;

	/*
	 * Translator name derived from rule group name with suffix removed.
	 */
	char		*np_name;

	/*
	 * Direction derived from rule group name used by creator.
	 */
	int		np_dir;

	/*
	 * Interface name.  Derived from rule attach point.
	 */
	char		np_ifname[IFNAMSIZ];

	/* Parameters from rule rproc config */
	struct in6_addr	np_in_prefix;
	uint8_t		np_in_prefixlen;
	struct in6_addr	np_out_prefix;
	uint8_t		np_out_prefixlen;
	bool		np_do_icmp_error;

	/* Calculated once at rproc creation */
	uint16_t	np_adjustment;
	uint8_t		np_adj_prefixlen;

	/*
	 * Valid for inside to outside rproc when inside prefix is shorter
	 * than outside prefix
	 */
	struct in6_addr	np_non_overlapping_mask;

	/* Per-core stats. Must be last */
	struct nptv6_stats np_stats[0];
};

/* Total drops */
static uint64_t nptv6_total_drops(struct nptv6 *np)
{
	uint64_t total = 0;
	uint i;

	FOREACH_DP_LCORE(i) {
		total += np->np_stats[i].ns_drops;
	}
	return total;
}

/*
 * Write json for one NPTv6 object
 */
static void
nptv6_jsonw(json_writer_t *json, struct nptv6 *np)
{
	char str1[INET6_ADDRSTRLEN+5];
	char str2[INET6_ADDRSTRLEN+5];

	/* Inside prefix */
	inet_ntop(AF_INET6, np->np_in_prefix.s6_addr, str1, sizeof(str1));
	snprintf(str1 + strlen(str1), sizeof(str1) - strlen(str1), "/%u",
		 np->np_in_prefixlen);

	/* Outside prefix */
	inet_ntop(AF_INET6, np->np_out_prefix.s6_addr, str2, sizeof(str2));
	snprintf(str2 + strlen(str2), sizeof(str2) - strlen(str2), "/%u",
		 np->np_out_prefixlen);

	jsonw_string_field(json, "interface", np->np_ifname);
	jsonw_string_field(json, "name", np->np_name);
	jsonw_string_field(json, "direction",
			   np->np_dir == PFIL_IN ? "in" : "out");
	jsonw_string_field(json, "inside", str1);
	jsonw_string_field(json, "outside", str2);

	snprintf(str1, sizeof(str1), "0x%04X", np->np_adjustment);
	jsonw_string_field(json, "adjustment", str1);

	if (np->np_do_icmp_error)
		jsonw_bool_field(json, "icmperr", true);

	struct npf_rule_stats rs;

	jsonw_name(json, "stats");
	jsonw_start_object(json);

	if (np->np_rl) {
		rule_sum_stats(np->np_rl, &rs);
		jsonw_uint_field(json, "bytes", rs.bytes_ct);
		jsonw_uint_field(json, "packets", rs.pkts_ct);
	}
	jsonw_uint_field(json, "drops", nptv6_total_drops(np));

	jsonw_end_object(json);
}

/*
 * Parse an NPTv6 rproc item/value pair.  Item should be one of:
 *   "inside", "outside", or "icmperr".
 */
static int
nptv6_parse_param(struct nptv6 *np, char *item, char *value)
{
	sa_family_t af;
	bool negate;
	int rc;

	if (!strcmp(item, "icmperr"))
		np->np_do_icmp_error =
			(strcmp(value, "no") == 0) ? false : true;
	else if (!strcmp(item, "inside")) {
		rc = npf_parse_ip_addr(value, &af, &np->np_in_prefix,
				       &np->np_in_prefixlen, &negate);

		if (rc < 0 || af != AF_INET6)
			return -EINVAL;

	} else if (!strcmp(item, "outside")) {
		rc = npf_parse_ip_addr(value, &af, &np->np_out_prefix,
				       &np->np_out_prefixlen, &negate);

		if (rc < 0 || af != AF_INET6)
			return -EINVAL;
	} else
		return -EINVAL;

	return 0;
}

/*
 * Validate rproc parameters derived from the rproc string and stored in nptv6
 * structure.
 */
static int
nptv6_validate_params(struct nptv6 *np)
{
	if (np->np_in_prefixlen < NPTV6_PREFIXLEN_MIN ||
	    np->np_in_prefixlen > NPTV6_PREFIXLEN_MAX)
		return -EINVAL;

	if (IN6_IS_ADDR_MULTICAST(&np->np_in_prefix) ||
	    IN6_IS_ADDR_UNSPECIFIED(&np->np_in_prefix) ||
	    IN6_IS_ADDR_LINKLOCAL(&np->np_in_prefix))
		return -EINVAL;

	if (np->np_out_prefixlen < NPTV6_PREFIXLEN_MIN ||
	    np->np_out_prefixlen > NPTV6_PREFIXLEN_MAX)
		return -EINVAL;

	if (IN6_IS_ADDR_MULTICAST(&np->np_out_prefix) ||
	    IN6_IS_ADDR_UNSPECIFIED(&np->np_out_prefix) ||
	    IN6_IS_ADDR_LINKLOCAL(&np->np_out_prefix))
		return -EINVAL;

	/*
	 * check that the zero-extended prefixes are not equal
	 */
	struct in6_addr inner = IN6ADDR_ANY_INIT; /* All zeros */
	struct in6_addr outer = IN6ADDR_ANY_INIT; /* All zeros */

	in6_prefix_cpy(&inner, &np->np_in_prefix, np->np_in_prefixlen);

	in6_prefix_cpy(&outer, &np->np_out_prefix, np->np_out_prefixlen);

	if (in6_prefix_eq(&inner, &outer, MAX(np->np_in_prefixlen,
					      np->np_out_prefixlen)))
		return -EINVAL;

	return 0;
}

/*
 * Return one's complement sum of an array of numbers.
 */
static uint16_t sum1(const uint16_t *numbers, int count)
{
	/* multiply count by 2 to get number of bytes */
	uint16_t result = in_cksum(numbers, count<<1);
	return ~result & 0xFFFF;
}

/*
 * One's complement sum.
 * return number1 + number2
 */
static inline uint16_t add1(uint16_t  number1, uint16_t  number2)
{
	return ip_partial_chksum_adjust(0, ~number1, number2);
}

/*
 * One's complement difference.
 * return number1 - number2
 */
static inline uint16_t sub1(uint16_t  number1, uint16_t  number2)
{
	return ip_partial_chksum_adjust(0, ~number1, ~number2);
}

/*
 * nptv6_adj_prefixlen and nptv6_adj_word determine which 16-bit word we
 * start with when determining where to write the adjustment value.
 *
 * Take the greater of the inner and outer prefix lengths, round up to
 * multiple of 16 if necessary, then divide by 16.  This is calculated just
 * once at configuration time, and stored in np_adj_prefixlen.
 */
static inline uint
nptv6_adj_prefixlen(uint in_prefixlen, uint out_prefixlen)
{
	uint adj_prefixlen = MAX(in_prefixlen, out_prefixlen);

	if (adj_prefixlen < 48)
		adj_prefixlen = 48;

	return adj_prefixlen;
}

static inline uint
nptv6_adj_word(uint adj_prefixlen)
{
	/* Round up to multiple of 16 if necessary */
	return (adj_prefixlen >> 4) + ((adj_prefixlen & 0xF) ? 1 : 0);
}

/*
 * Calculate adjustment value from internal and external prefixes.
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
nptv6_adjustment(uint8_t adj_prefixlen,
		 struct in6_addr *inner_pfx, uint inner_mask,
		 struct in6_addr *outer_pfx, uint outer_mask)
{
	struct in6_addr inner = IN6ADDR_ANY_INIT; /* All zeros */
	struct in6_addr outer = IN6ADDR_ANY_INIT; /* All zeros */

	/* Copy prefixs. Host parts remain zero. */
	in6_prefix_cpy(&inner, inner_pfx, inner_mask);
	in6_prefix_cpy(&outer, outer_pfx, outer_mask);

	/*
	 * Which uint16_t word will the adjustment be applied to?  From this
	 * we can determine the number of words in the (zero-extended)
	 * prefixes to perform the 1's complement calculations on.
	 */
	uint nwords = nptv6_adj_word(adj_prefixlen);

	uint16_t inner64 = sum1(&inner.s6_addr16[0], nwords);
	uint16_t outer64 = sum1(&outer.s6_addr16[0], nwords);
	uint16_t adjustment = sub1(inner64, outer64);

	return adjustment;
}

/*
 * Calculate the NTPv6 "adjustment" value and initial word position within an
 * address to "adjust".  These are calculated once, and are effectively
 * constant for the lifetime of the NPTv6 translator configuration.
 */
static void
nptv6_calc_adjustment(struct nptv6 *np)
{
	/*
	 * Determine what prefix length to use for the adjustment
	 */
	np->np_adj_prefixlen = nptv6_adj_prefixlen(np->np_in_prefixlen,
						   np->np_out_prefixlen);

	/*
	 * Calculate the adjustment and which uint16_t word we will write the
	 * adjustment to.
	 */
	np->np_adjustment = nptv6_adjustment(np->np_adj_prefixlen,
					     &np->np_in_prefix,
					     np->np_in_prefixlen,
					     &np->np_out_prefix,
					     np->np_out_prefixlen);
}

/*
 * Non-overlapping mask.  E.g. if len1 is 48 and len2 is 62 then mask is:
 * 0:0:0:fffc::0
 */
static void
nptv6_non_overlapping_mask(struct in6_addr *mask, uint len1, uint len2)
{
	struct in6_addr mask1, mask2;
	uint i;

	/* sanity check */
	if (len1 > 128 || len2 > 128)
		return;

	in6_prefixlen2mask(&mask1, len1);
	in6_prefixlen2mask(&mask2, len2);

	for (i = 0; i < 4; i++)
		mask->s6_addr32[i] = mask1.s6_addr32[i] ^ mask2.s6_addr32[i];
}

/*
 * If inside prefix is shorter than outside prefix then check that no bits are
 * set in the parts of the address that match the non-overlapping mask.
 */
static inline bool
nptv6_any_masked_bits_set(struct in6_addr *mask, struct in6_addr *addr)
{
	if (((uint64_t *)(addr))[0] & ((uint64_t *)(mask))[0])
		return true;

	if (((uint64_t *)(addr))[1] & ((uint64_t *)(mask))[1])
		return true;

	return false;
}

/*
 * Create and initialize nptv6 structure.
 *
 * On input *npp points to NPTv6 params to lookup.  On output *npp points a
 * new instance if successful.  Always consumes rg_name.
 */
static int
nptv6_create(struct nptv6 **npp, char *rg_name, npf_rule_t *rl)
{
	struct nptv6 *new = zmalloc_aligned(sizeof(*new) +
					    (sizeof(struct nptv6_stats) *
					     (get_lcore_max() + 1)));

	if (!new) {
		free(rg_name);
		return -ENOMEM;
	}

	memcpy(new, *npp, sizeof(*new));
	new->np_name = rg_name;
	new->np_rl = rl;
	new->np_ifname[0] = '\0';

	/*
	 * Lookup the rule attach point to get the interface name.
	 */
	enum npf_attach_type attach_type;
	const char *attach_point;

	if (!npf_rule_get_attach_point(rl, &attach_type, &attach_point) &&
		strnlen(attach_point, IFNAMSIZ) < IFNAMSIZ) {
		strncpy(new->np_ifname, attach_point, IFNAMSIZ);
	}

	/*
	 * Lookup the rule to get the direction
	 */
	new->np_dir = npf_rule_get_dir(rl);
	if (new->np_dir != PFIL_IN && new->np_dir != PFIL_OUT) {
		free(new->np_name);
		free(new);
		return -EINVAL;
	}

	/* Calculate adjustment value once */
	nptv6_calc_adjustment(new);

	if (new->np_dir == PFIL_OUT &&
	    new->np_in_prefixlen < new->np_out_prefixlen)
		nptv6_non_overlapping_mask(&new->np_non_overlapping_mask,
					   new->np_in_prefixlen,
					   new->np_out_prefixlen);

	*npp = new;

	return 0;
}

/*
 * NPTv6 Rproc Creator
 */
static int
nptv6_rproc_ctor(npf_rule_t *rl, const char *params, void **handle)
{
	/* Use stack variable to store parsed params */
	struct nptv6 nptv6 = {0};
	struct nptv6 *np = &nptv6;
	char *rg_name;

	rg_name = strdup(npf_rule_get_name(rl));
	if (!rg_name)
		return -ENOMEM;

	/* Duplicate the comma-separated argument list. */
	char *args = strdup(params);
	if (!args) {
		free(rg_name);
		return -ENOMEM;
	}

	/*
	 * Set any non-zero defaults here
	 */
	np->np_do_icmp_error = true;

	/*
	 * Parse the duplicate argument list.  Store results in argv[] array,
	 * where each entry will be of the form "item=value".  Each entry in
	 * argv[] will point into the args string.
	 *
	 * args is of the form "a=x,b=y,c=z".  We only expect at most three
	 * parameters - inside prefix, outside prefix, and icmp error setting.
	 */
	char *argv[3];
	uint argc = 0, i;
	char *arg, *nxt, *c;
	int rc;

	/* Split args into separate strings "a=x", "b=y" etc. */
	for (arg = args, nxt = NULL; arg && argc < ARRAY_SIZE(argv);
	     arg = nxt, nxt = NULL) {
		c = strchr(arg, ',');
		if (c) {
			*c = '\0';
			nxt = c+1;
		}
		if (strchr(arg, '='))
			argv[argc++] = arg;
	}

	/*
	 * Parse the item/value pairs e.g "a=x", and store results in nptv6
	 * structure.
	 */
	for (i = 0; i < argc; i++) {
		c = strchr(argv[i], '=');
		if (!c)
			continue;

		*c = '\0';
		c += 1;

		/* argv[i] points to the item, 'c' points to the value */

		rc = nptv6_parse_param(np, argv[i], c);
		if (rc) {
			free(args);
			free(rg_name);
			return rc;
		}
	}
	/* We are now finished with the args string and argv[] array */
	free(args);

	/* Validate parameters we have just stored in local nptv6 structure */
	rc = nptv6_validate_params(np);
	if (rc) {
		free(rg_name);
		return rc;
	}

	/*
	 * Create nptv6 structure and add to global list.  Consumes rg_name.
	 * 'np' changed to point to new malloc'd structure.
	 */
	rc = nptv6_create(&np, rg_name, rl);
	if (rc)
		return rc;

	*handle = np;
	return 0;
}

/*
 * NPTv6 Rproc Destructor
 */
static void
nptv6_rproc_dtor(void *handle)
{
	struct nptv6 *np = handle;

	if (np) {
		if (np->np_name)
			free(np->np_name);
		free(np);
	}
}

/*
 * Can an adjustment be made to the address?
 *
 * This also determines which 16-bit word to add/subtract the adjustment
 * to/from.
 *
 * At configuration time we calculate 'np_adj_prefixlen' by taking the greater
 * of the inner and outer prefix lengths, round up to multiple of 16 if
 * necessary, then divide by 16.  Then from np_adj_prefixlen we calculate an
 * initial 'adj_word' value that is passed into this function.
 *
 * [3.4] NPTv6 with a /48 or Shorter Prefix
 *
 * When an NPTv6 Translator is configured with internal and external prefixes
 * that are 48 bits in length (a /48) or shorter, the adjustment MUST be added
 * to or subtracted from bits 48..63 of the address.
 *
 * [3.5] NPTv6 with a /49 or Longer Prefix
 *
 * When an NPTv6 Translator is configured with internal and external prefixes
 * that are longer than 48 bits in length (such as a /52, /56, or /60), the
 * adjustment must be added to or subtracted from one of the words in bits
 * 64..79, 80..95, 96..111, or 112..127 of the address.  While the choice of
 * word is immaterial as long as it is consistent, these words MUST be
 * inspected in that sequence and the first that is not initially 0xFFFF
 * chosen, for consistency's sake.
 */
static bool
nptv6_is_addr_translatable(struct in6_addr *addr, uint *adj_word)
{
	uint w = *adj_word;

	assert(*adj_word >= 3);

	if (w > 3) {
		for (; w < 8; w++)
			if (addr->s6_addr16[w] != 0xFFFF)
				break;

		if (w == 8)
			return false;
	} else {
		/* adj_word == 3 */
		if (addr->s6_addr16[3] == 0xFFFF)
			return false;
	}

	*adj_word = w;
	return true;
}

/*
 * Translate address.  Returns 0 if successful.  Else return ICMPv6 error
 * type.
 */
static int
nptv6_translate_addr(const struct nptv6 *np, struct in6_addr *addr,
		     const struct in6_addr *pfx, uint dir)
{
	uint adj_word;

	adj_word = nptv6_adj_word(np->np_adj_prefixlen);

	/*
	 * Is the address translatable? If so, which word do we apply the
	 * adjustment to?
	 */
	if (unlikely(!nptv6_is_addr_translatable(addr, &adj_word)))
		return ICMP6_DST_UNREACH;

	/* Change prefix */
	in6_prefix_cpy(addr, pfx, np->np_adj_prefixlen);

	/* Write adjustment word */
	if (dir == PFIL_OUT)
		addr->s6_addr16[adj_word] = add1(addr->s6_addr16[adj_word],
						 np->np_adjustment);
	else
		addr->s6_addr16[adj_word] = sub1(addr->s6_addr16[adj_word],
						 np->np_adjustment);

	/* Change 0xffff to 0 */
	if (unlikely(addr->s6_addr16[adj_word] == 0xFFFF))
		addr->s6_addr16[adj_word] = 0;

	/*
	 * Has the adjustment resulted in an IID of zero?  If the NPTv6 prefix
	 * length is greater than 48 then the adjustment will be applied to
	 * the IID part of the address.
	 */
	if (np->np_adj_prefixlen > 48 && in6_is_addr_id_zero(addr))
		return ICMP6_PARAM_PROB;

	return 0;
}

/*
 * Translate ICMPv6 inner packet.
 */
static void
nptv6_translate_icmp(const struct nptv6 *np, const struct in6_addr *pfx,
		     struct rte_mbuf *mbuf, uint dir)
{
	const struct in6_addr *match;
	struct in6_addr addr;
	void *n_ptr;
	uint plen;
	int rc;

	n_ptr = rte_pktmbuf_mtod_offset(mbuf, char *, pktmbuf_l2_len(mbuf));

	if (dir == PFIL_IN) {
		/*
		 * External-to-internal: Translate inner src if its
		 * prefix matches the external network prefix
		 */
		rc = nbuf_advfetch(&mbuf, &n_ptr,
				   pktmbuf_l3_len(mbuf) +
				   sizeof(struct icmp6_hdr) +
				   offsetof(struct ip6_hdr, ip6_src),
				   sizeof(addr), &addr);
		if (rc)
			return;

		match = &np->np_out_prefix;
		plen = np->np_out_prefixlen;
	} else {
		/*
		 * Internal-to-external: Translate inner dst if its
		 * prefix matches the internal network prefix
		 */
		rc = nbuf_advfetch(&mbuf, &n_ptr,
				   pktmbuf_l3_len(mbuf) +
				   sizeof(struct icmp6_hdr) +
				   offsetof(struct ip6_hdr, ip6_dst),
				   sizeof(addr), &addr);
		if (rc)
			return;

		match = &np->np_in_prefix;
		plen = np->np_in_prefixlen;
	}

	if (!in6_prefix_eq(&addr, match, plen))
		return;

	/*
	 * Do the translation.  We do not care if the inner address is
	 * translatable or not.
	 */
	(void)nptv6_translate_addr(np, &addr, pfx, dir);

	/* Write translated address back to packet */
	nbuf_advstore(&mbuf, &n_ptr, 0, sizeof(addr), &addr);
}

/*
 * NPTv6 Rproc Translator.
 */
npf_decision_t
nptv6_translate(npf_cache_t *npc, struct rte_mbuf **nbuf, void *arg,
		int *icmp_type, int *icmp_code)
{
	struct nptv6 *np = arg;
	struct ip6_hdr *ip6 = &npc->npc_ip.v6;
	struct rte_mbuf *mbuf;
	const struct in6_addr *pfx;
	struct in6_addr *addr;
	struct in6_addr trans;
	int icmp;

	uint hdr_len = pktmbuf_l2_len(*nbuf) + pktmbuf_l3_len(*nbuf);

	if (unlikely(npf_iscached(npc, NPC_ICMP_ERR)))
		hdr_len += sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr);

	if (pktmbuf_prepare_for_header_change(nbuf, hdr_len) != 0) {
		nptv6_drops_inc(np);
		return NPF_DECISION_BLOCK;
	}
	mbuf = *nbuf;

	/*
	 * Which address are we translating?
	 */
	if (np->np_dir == PFIL_OUT) {
		/* Source prefix translation */
		addr = &ip6->ip6_src;
		pfx = &np->np_out_prefix;

		/*
		 * If inside prefix is shorter than outside prefix then check
		 * that no bits are set in the parts of the address that match
		 * the non-overlapping mask.
		 */
		if (np->np_in_prefixlen < np->np_out_prefixlen &&
		    nptv6_any_masked_bits_set(&np->np_non_overlapping_mask,
					      addr)) {
			nptv6_drops_inc(np);

			if (np->np_do_icmp_error) {
				*icmp_type = ICMP6_DST_UNREACH;
				*icmp_code = ICMP6_DST_UNREACH_ADDR;
			}

			return NPF_DECISION_BLOCK;
		}
	} else {
		/* Destination prefix translation */
		addr = &ip6->ip6_dst;
		pfx = &np->np_in_prefix;
	}

	/*
	 * Copy the address then do the translation
	 */
	memcpy(trans.s6_addr, addr->s6_addr, 16);

	icmp = nptv6_translate_addr(np, &trans, pfx, np->np_dir);

	if (unlikely(icmp != 0)) {
		nptv6_drops_inc(np);

		if (np->np_do_icmp_error) {
			if (icmp == ICMP6_DST_UNREACH) {
				*icmp_type = ICMP6_DST_UNREACH;
				*icmp_code = ICMP6_DST_UNREACH_ADDR;
			} else if (icmp == ICMP6_PARAM_PROB) {
				*icmp_type = ICMP6_PARAM_PROB;
				*icmp_code = ICMP6_PARAMPROB_HEADER;
			}
		}
		return NPF_DECISION_BLOCK;
	}

	/*
	 * Write the translated address back to the packet, and update cache
	 */
	void *n_ptr = pktmbuf_mtol3(mbuf, void *);

	npf_rwrip6(npc, mbuf, n_ptr, np->np_dir, &trans);

	/*
	 * Translate inner IPv6 header for ICMPv6 Destination Unreachable,
	 * Packet Too Big, Time Exceeded, and Parameter Problem messages.
	 */
	if (unlikely(npf_iscached(npc, NPC_ICMP_ERR)))
		nptv6_translate_icmp(np, pfx, mbuf, np->np_dir);

	return NPF_DECISION_PASS;
}

/*
 * NPTv6 rproc JSON
 */
static void
nptv6_rproc_json(json_writer_t *json,
		 npf_rule_t *rl __unused,
		 const char *params __unused,
		 void *handle)
{
	struct nptv6 *np = handle;
	nptv6_jsonw(json, np);
}

/* rproc ops */
const npf_rproc_ops_t npf_nptv6_ops = {
	.ro_name   = "nptv6",
	.ro_type   = NPF_RPROC_TYPE_HANDLE,
	.ro_id     = NPF_RPROC_ID_NPTV6,
	.ro_bidir  = false,
	.ro_ctor   = nptv6_rproc_ctor,
	.ro_dtor   = nptv6_rproc_dtor,
	.ro_json   = nptv6_rproc_json,
};
