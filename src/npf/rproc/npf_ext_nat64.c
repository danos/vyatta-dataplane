/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * NAT64 and NAT46 rproc
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
#include "npf/npf.h"
#include "npf/npf_cache.h"
#include "npf/config/npf_config.h"
#include "npf/npf_cmd.h"
#include "npf/npf_ruleset.h"
#include "npf/npf_rule_gen.h"
#include "npf/npf_addrgrp.h"
#include "npf/rproc/npf_rproc.h"
#include "npf/rproc/npf_ext_nat64.h"
#include "npf/npf_tblset.h"

/*
 * Create and initialize nat64 structure.
 *
 * On input *n6p points to the nat64 validated params.  On output *n6p points
 * a new instance if successful.
 */
static int
nat64_create(struct nat64 **n6p, npf_rule_t *rl)
{
	struct nat64 *new = zmalloc_aligned(sizeof(*new));
	int rc;

	if (!new)
		return -ENOMEM;

	memcpy(new, *n6p, sizeof(*new));
	new->n6_rl = rl;

	if (new->n6_src.nm_type == NPF_NAT64_OVERLOAD) {
		uint32_t table_id = NPF_TBLID_NONE;
		uint32_t flags = NPF_NAT_PINHOLE;
		uint8_t type = NPF_NATOUT;
		uint32_t match_mask = 0;
		uint8_t addr_sz = 4;

		if (new->n6_src.nm_addr_table_id != NPF_TBLID_NONE) {
			table_id = new->n6_src.nm_addr_table_id;
			flags |= NPF_NAT_TABLE;
		}

		/*
		 * Create an address-port map and set r_natp pointer in rule
		 * to point to it
		 */
		rc = npf_create_natpolicy(rl, type, flags, table_id, addr_sz,
					  &new->n6_src.nm_start_addr,
					  &new->n6_src.nm_stop_addr,
					  match_mask,
					  new->n6_src.nm_start_port,
					  new->n6_src.nm_stop_port);
		if (rc != 0)
			goto error;
	}

	*n6p = new;

	return 0;

error:
	free(new);
	return rc;
}

/*
 * Parse rproc address range.  'value' is of the form "10.10.1.1-10.10.1.8".
 */
static int
nat64_process_range(uint8_t *addr_sz, npf_addr_t *taddr,
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

/*
 * Parse nat64 rproc parameters
 *
 * This parses one "item=value" pair from inside the braces of a rule
 * i.e. from "handle=nat64(item=value,item=value)".
 */
static int
nat64_parse_params(struct nat64 *n6, char *item, char *value)
{
	bool negate;
	int rc;

	if (!strcmp(item, "saddr")) {
		/*
		 * Source address or prefix
		 */
		rc = npf_parse_ip_addr(value, &n6->n6_src.nm_af,
				       &n6->n6_src.nm_addr,
				       &n6->n6_src.nm_mask, &negate);

		if (rc < 0)
			return -EINVAL;
	} else if (!strcmp(item, "daddr")) {
		/*
		 * Destination address or prefix
		 */
		rc = npf_parse_ip_addr(value, &n6->n6_dst.nm_af,
				       &n6->n6_dst.nm_addr,
				       &n6->n6_dst.nm_mask, &negate);

		if (rc < 0)
			return -EINVAL;
	} else if (!strcmp(item, "spl")) {
		char *endp;
		ulong pfxlen;

		pfxlen = strtoul(value, &endp, 10);
		if (endp == value || pfxlen > 128)
			return -EINVAL;
		n6->n6_src.nm_mask = pfxlen;
	} else if (!strcmp(item, "dpl")) {
		char *endp;
		ulong pfxlen;

		pfxlen = strtoul(value, &endp, 10);
		if (endp == value || pfxlen > 128)
			return -EINVAL;
		n6->n6_dst.nm_mask = pfxlen;
	} else if (!strcmp(item, "srange")) {
		/*
		 * Source address range, for use with NPF_NAT64_OVERLOAD
		 */
		uint8_t addr_sz;

		rc = nat64_process_range(&addr_sz,
					 &n6->n6_src.nm_start_addr,
					 &n6->n6_src.nm_stop_addr,
					 value);
		if (rc < 0)
			return -EINVAL;

		n6->n6_src.nm_af = (addr_sz == 4 ? AF_INET : AF_INET6);

		/* Use all ports for each address in pool */
		n6->n6_src.nm_start_port = 1;
		n6->n6_src.nm_stop_port = 65535;

	} else if (!strcmp(item, "sgroup")) {
		/*
		 * Source address group, for use with NPF_NAT64_OVERLOAD
		 */
		uint32_t table_id;

		rc = npf_addrgrp_name2tid(value, &table_id);
		if (rc < 0)
			return rc;

		n6->n6_src.nm_addr_table_id = table_id;
		/* We are assuming the address-group contains v4 addrs */
		n6->n6_src.nm_af = AF_INET;

	} else if (!strcmp(item, "stype") || !strcmp(item, "dtype")) {
		bool is_src = !strcmp(item, "stype");
		enum npf_nat64_map_type type = NPF_NAT64_NONE;

		if (!strcmp(value, "rfc6052"))
			type = NPF_NAT64_RFC6052;
		else if (!strcmp(value, "one2one"))
			type = NPF_NAT64_ONE2ONE;
		else if (!strcmp(value, "overload"))
			type = NPF_NAT64_OVERLOAD;

		if (is_src)
			n6->n6_src.nm_type = type;
		else
			n6->n6_dst.nm_type = type;
	} else if (!strcmp(item, "dport")) {
		char *endp;
		ulong port;

		port = strtoul(value, &endp, 10);
		if (endp == value || port > 65535)
			return -EINVAL;
		n6->n6_dst.nm_start_port = htons(port);
	} else if (!strcmp(item, "log")) {
		char *endp;
		ulong log;

		log = strtoul(value, &endp, 10);
		if (endp == value || log > 255)
			return -EINVAL;
		n6->n6_log = log;
	}
	return 0;
}

/*
 * Validate nat64 mapping configuration
 */
static int
nat64_validate_mapping(struct nat64_map *nm, bool is_src)
{
	switch (nm->nm_type) {
	case NPF_NAT64_RFC6052:
		/* Valid values are 32, 40, 48, 56, 64 or 96 */
		if (nm->nm_mask < 32 || nm->nm_mask > 96 ||
		    (nm->nm_mask & 0x3))
			return -EINVAL;
		break;
	case NPF_NAT64_ONE2ONE:
		if (nm->nm_mask !=
		    ((nm->nm_af == AF_INET) ? 32 : 128))
			return -EINVAL;
		break;
	case NPF_NAT64_OVERLOAD:
		/* Only v4 source addr pools are supported */
		if (!is_src || nm->nm_af != AF_INET)
			return -EINVAL;
		break;
	case NPF_NAT64_NONE:
		return -EINVAL;
	}
	return 0;
}

static int
nat64_validate_params(struct nat64 *n6)
{
	int rc;

	rc = nat64_validate_mapping(&n6->n6_src, true);
	if (rc < 0)
		return rc;

	rc = nat64_validate_mapping(&n6->n6_dst, false);
	if (rc < 0)
		return rc;

	return 0;
}

/*
 * Nat64 and nat46 rproc Constructor
 */
static int
common_rproc_ctor(npf_rule_t *rl, const char *params, void **handle,
		  enum npf_nat64_type type)
{
	/* Use stack variable to store parsed params */
	struct nat64 nat64 = {0};
	struct nat64 *n6 = &nat64;

	/* Duplicate the comma-separated argument list. */
	char *args = strdup(params);
	if (!args)
		return -ENOMEM;

	/*
	 * Parse the duplicate argument list.  Store results in argv[] array,
	 * where each entry will be of the form "item=value".  Each entry in
	 * argv[] will point into the args string.
	 *
	 * args is of the form "a=x,b=y,c=z".
	 */
	char *argv[12];
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

	/* Non-zero defaults */
	n6->n6_src.nm_addr_table_id = NPF_TBLID_NONE;

	/*
	 * Parse each of the item/value pairs e.g "a=x", and store results in
	 * nat64 structure.
	 */
	for (i = 0; i < argc; i++) {
		char *item = argv[i];

		c = strchr(item, '=');
		if (!c)
			continue;

		*c = '\0';
		c += 1;

		/* 'item' points to the item, 'c' points to the value */
		rc = nat64_parse_params(n6, item, c);
		if (rc) {
			free(args);
			return rc;
		}
	}
	/* We are now finished with the args string and argv[] array */
	free(args);

	n6->n6_type = type;

	rc = nat64_validate_params(n6);
	if (rc)
		return rc;

	rc = nat64_create(&n6, rl);
	if (rc)
		return rc;

	*handle = n6;
	return 0;
}

/*
 * Nat64 Rproc Constructor
 */
static int
nat64_rproc_ctor(npf_rule_t *rl, const char *params, void **handle)
{
	return common_rproc_ctor(rl, params, handle, N6_NAT64);
}

/*
 * Nat64 Rproc Destructor
 */
static void
nat64_rproc_dtor(void *handle)
{
	if (!handle)
		return;
	free(handle);
}

/*
 * Nat46 Rproc Constructor
 */
static int
nat46_rproc_ctor(npf_rule_t *rl, const char *params, void **handle)
{
	return common_rproc_ctor(rl, params, handle, N6_NAT46);
}

/*
 * Nat46 Rproc Destructor
 */
static void
nat46_rproc_dtor(void *handle)
{
	if (!handle)
		return;
	free(handle);
}

/*
 * Nat64 rproc ops.
 *
 * Does not use ro_match or ro_action operations.  We are only using the rproc
 * as a convenient way to attach a pointer to a nat64 object to a rule.
 */
const npf_rproc_ops_t npf_nat64_ops = {
	.ro_name   = "nat64",
	.ro_type   = NPF_RPROC_TYPE_HANDLE,
	.ro_id     = NPF_RPROC_ID_NAT64,
	.ro_bidir  = false,
	.ro_ctor   = nat64_rproc_ctor,
	.ro_dtor   = nat64_rproc_dtor,
};

/*
 * Nat46 rproc ops.
 *
 * Does not use ro_match or ro_action operations.  We are only using the rproc
 * as a convenient way to attach a pointer to a nat64 object to a rule.
 */
const npf_rproc_ops_t npf_nat46_ops = {
	.ro_name   = "nat46",
	.ro_type   = NPF_RPROC_TYPE_HANDLE,
	.ro_id     = NPF_RPROC_ID_NAT46,
	.ro_bidir  = false,
	.ro_ctor   = nat46_rproc_ctor,
	.ro_dtor   = nat46_rproc_dtor,
};
