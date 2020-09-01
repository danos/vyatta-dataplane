/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * npf return code counters
 */

#include <json_writer.h>

#include "util.h"
#include "pl_node.h"
#include "pipeline/nodes/pl_nodes_common.h"
#include "npf_shim.h"
#include "npf/zones/npf_zone_public.h"
#include "npf/npf_cmd.h"
#include "npf/npf_rc.h"

/*
 * The return codes are categorised into 4 main types
 */
enum rc_ctrl_cat {
	RC_CAT_PASS,
	RC_CAT_NOMATCH,
	RC_CAT_BLOCK,
	RC_CAT_DROP,
};
#define RC_CAT_LAST RC_CAT_DROP
#define RC_CAT_SZ (RC_CAT_LAST+1)
#define RC_CAT_ALL (RC_CAT_LAST+2)

static inline const char *rc_ctrl_cat2str(enum rc_ctrl_cat cat)
{
	switch (cat) {
	case RC_CAT_PASS:
		return "pass";
	case RC_CAT_NOMATCH:
		return "unmatched";
	case RC_CAT_BLOCK:
		return "block";
	case RC_CAT_DROP:
		return "drop";
	};
	return "unkn";
}

struct rc_ctrl {
	uint bm;	/* Bitmap of return-code types */
	uint cat;	/* Category - pass, block or drop */
};
static struct rc_ctrl npf_rc_ctrl[NPF_DIR_SZ][NPF_RC_SZ];

static void npf_rc_ctrl_init(void)
{
	static bool initd;
	enum npf_rc_dir dir;
	enum npf_rc_en rc;

	/* Only do once */
	if (initd)
		return;

	/*
	 * We use a bitmap to determine which return-codes are used by which
	 * return code types.  For example, fw6 does not use only of the NAT
	 * return codes.
	 */
	for (dir = 0; dir < NPF_DIR_SZ; dir++)
		for (rc = 0; rc < NPF_RC_SZ; rc++) {
			/* Init bitmap of rc types */
			switch (rc) {
			case NPF_RC_UNMATCHED:
			case NPF_RC_PASS:
			case NPF_RC_BLOCK:
			case NPF_RC_INTL:
				npf_rc_ctrl[dir][rc].bm = RCT_BIT_ALL;
				break;

			/* the following may occur from  npf cache */
			case NPF_RC_L3_HDR_VER:
			case NPF_RC_L3_HDR_LEN:
			case NPF_RC_NON_IP:
			case NPF_RC_L3_SHORT:
			case NPF_RC_L3_PROTO:
			case NPF_RC_L4_SHORT:
				npf_rc_ctrl[dir][rc].bm =
					(RCT_BIT_FW4 | RCT_BIT_FW6 |
					 RCT_BIT_NAT64 | RCT_BIT_L2 |
					 RCT_BIT_LOC | RCT_BIT_ACL4 |
					 RCT_BIT_ACL6);
				break;

			/* the following may occur via npf_state_inspect */
			case NPF_RC_ICMP_ECHO:
			case NPF_RC_TCP_SYN:
			case NPF_RC_TCP_STATE:
			case NPF_RC_TCP_WIN:
				npf_rc_ctrl[dir][rc].bm =
					(RCT_BIT_FW4 | RCT_BIT_FW6 |
					 RCT_BIT_NAT64 | RCT_BIT_LOC);
				break;

			/* the following may occur when creating a session */
			case NPF_RC_ENOSTR:
			case NPF_RC_SESS_ENOMEM:
			case NPF_RC_SESS_LIMIT:
			case NPF_RC_SESS_HOOK:
			case NPF_RC_DP_SESS_ESTB:
				npf_rc_ctrl[dir][rc].bm =
					(RCT_BIT_FW4 | RCT_BIT_FW6 |
					 RCT_BIT_NAT64 | RCT_BIT_LOC);
				break;

			/* NAT and NAT64 */
			case NPF_RC_MBUF_ENOMEM:
			case NPF_RC_NAT_ENOSPC:
			case NPF_RC_NAT_ENOMEM:
			case NPF_RC_NAT_EADDRINUSE:
			case NPF_RC_NAT_ERANGE:
			case NPF_RC_NAT_E2BIG:
			case NPF_RC_ICMP_ERR_NAT:
				npf_rc_ctrl[dir][rc].bm |=
					(RCT2BIT(NPF_RCT_FW4 | NPF_RCT_NAT64));
				break;

			/* NAT only */
			case NPF_RC_ALG_EEXIST:
			case NPF_RC_ALG_ERR:
				npf_rc_ctrl[dir][rc].bm |=
					(RCT2BIT(NPF_RCT_FW4));
				break;

			/* NAT64 only */
			case NPF_RC_NAT64_4T6:
			case NPF_RC_NAT64_6T4:
			case NPF_RC_NAT64_ENOSPC:
			case NPF_RC_NAT64_ENOMEM:
			case NPF_RC_NAT64_6052:
			case NPF_RC_L4_PROTO:
			case NPF_RC_MBUF_ERR:
				npf_rc_ctrl[dir][rc].bm |=
					RCT2BIT(NPF_RCT_NAT64);
				break;
			}

			/* Init category */
			switch (rc) {
			case NPF_RC_PASS:
			case NPF_RC_ENOSTR:
			case NPF_RC_NAT64_4T6:
			case NPF_RC_NAT64_6T4:
				npf_rc_ctrl[dir][rc].cat = RC_CAT_PASS;
				break;
			case NPF_RC_UNMATCHED:
				npf_rc_ctrl[dir][rc].cat = RC_CAT_NOMATCH;
				break;
			case NPF_RC_BLOCK:
				npf_rc_ctrl[dir][rc].cat = RC_CAT_BLOCK;
				break;
			case NPF_RC_L3_HDR_VER:
			case NPF_RC_L3_HDR_LEN:
			case NPF_RC_NON_IP:
			case NPF_RC_L3_PROTO:
			case NPF_RC_L4_PROTO:
			case NPF_RC_L4_SHORT:
			case NPF_RC_ICMP_ECHO:
			case NPF_RC_TCP_SYN:
			case NPF_RC_TCP_STATE:
			case NPF_RC_TCP_WIN:
			case NPF_RC_SESS_ENOMEM:
			case NPF_RC_SESS_LIMIT:
			case NPF_RC_SESS_HOOK:
			case NPF_RC_DP_SESS_ESTB:
			case NPF_RC_L3_SHORT:
			case NPF_RC_MBUF_ENOMEM:
			case NPF_RC_MBUF_ERR:
			case NPF_RC_NAT_ENOSPC:
			case NPF_RC_NAT_ENOMEM:
			case NPF_RC_NAT_EADDRINUSE:
			case NPF_RC_NAT_ERANGE:
			case NPF_RC_NAT_E2BIG:
			case NPF_RC_ICMP_ERR_NAT:
			case NPF_RC_ALG_EEXIST:
			case NPF_RC_ALG_ERR:
			case NPF_RC_NAT64_ENOSPC:
			case NPF_RC_NAT64_ENOMEM:
			case NPF_RC_NAT64_6052:
			case NPF_RC_INTL:
				npf_rc_ctrl[dir][rc].cat = RC_CAT_DROP;
				break;
			}
		}


	initd = true;
}

static bool
npf_rc_enabled(enum npf_rc_type rct, enum npf_rc_dir dir, enum npf_rc_en rc)
{
	if (rct >= NPF_RCT_SZ || dir >= NPF_DIR_SZ || rc >= NPF_RC_SZ)
		return false;

	return ((npf_rc_ctrl[dir][rc].bm & RCT2BIT(rct)) != 0);
}

/*
 * Create npf counters.  A set of counters is created per-interface.
 */
struct npf_rc_counts *npf_rc_counts_create(void)
{
	struct npf_rc_counts *rcc;

	assert(PFIL2RC(PFIL_IN) == NPF_RC_IN);
	assert(PFIL2RC(PFIL_OUT) == NPF_RC_OUT);

	rcc = zmalloc_aligned((get_lcore_max() + 1) *
			      sizeof(struct npf_rc_counts));

	return rcc;
}

void npf_rc_counts_destroy(struct npf_rc_counts **rcc)
{
	if (*rcc) {
		free(*rcc);
		*rcc = NULL;
	}
}

/*
 * return-code short string
 */
const char *npf_rc_str(int rc)
{
	if (rc < 0)
		rc = -rc;
	if (rc > NPF_RC_LAST)
		rc = NPF_RC_INTL;

	switch ((enum npf_rc_en)rc) {
	case NPF_RC_UNMATCHED:
		return "RC_UNMATCHED";
	case NPF_RC_PASS:
		return "RC_PASS";
	case NPF_RC_BLOCK:
		return "RC_BLOCK";
	case NPF_RC_L3_HDR_VER:
		return "RC_L3_HDR_VER";
	case NPF_RC_L3_HDR_LEN:
		return "RC_L3_HDR_LEN";
	case NPF_RC_NON_IP:
		return "RC_NON_IP";
	case NPF_RC_L3_SHORT:
		return "RC_L3_SHORT";
	case NPF_RC_L4_SHORT:
		return "RC_L4_SHORT";
	case NPF_RC_L3_PROTO:
		return "RC_L3_PROTO";
	case NPF_RC_L4_PROTO:
		return "RC_L4_PROTO";
	case NPF_RC_ICMP_ECHO:
		return "RC_ICMP_ECHO";
	case NPF_RC_ENOSTR:
		return "RC_ENOSTR";
	case NPF_RC_TCP_SYN:
		return "RC_TCP_SYN";
	case NPF_RC_TCP_STATE:
		return "RC_TCP_STATE";
	case NPF_RC_TCP_WIN:
		return "RC_TCP_WIN";
	case NPF_RC_SESS_ENOMEM:
		return "RC_SESS_ENOMEM";
	case NPF_RC_SESS_LIMIT:
		return "RC_SESS_LIMIT";
	case NPF_RC_SESS_HOOK:
		return "RC_SESS_HOOK";
	case NPF_RC_DP_SESS_ESTB:
		return "RC_DP_SESS_ESTB";
	case NPF_RC_MBUF_ENOMEM:
		return "RC_MBUF_ENOMEM";
	case NPF_RC_MBUF_ERR:
		return "RC_MBUF_ERR";
	case NPF_RC_NAT_ENOSPC:
		return "RC_NAT_ENOSPC";
	case NPF_RC_NAT_ENOMEM:
		return "RC_NAT_ENOMEM";
	case NPF_RC_NAT_EADDRINUSE:
		return "RC_NAT_EADDRINUSE";
	case NPF_RC_NAT_ERANGE:
		return "RC_NAT_ERANGE";
	case NPF_RC_NAT_E2BIG:
		return "RC_NAT_E2BIG";
	case NPF_RC_ICMP_ERR_NAT:
		return "RC_ICMP_ERR_NAT";
	case NPF_RC_ALG_EEXIST:
		return "RC_ALG_EEXIST";
	case NPF_RC_ALG_ERR:
		return "RC_ALG_ERR";
	case NPF_RC_NAT64_4T6:
		return "RC_NAT64_4T6";
	case NPF_RC_NAT64_6T4:
		return "RC_NAT64_6T4";
	case NPF_RC_NAT64_ENOSPC:
		return "RC_NAT64_ENOSPC";
	case NPF_RC_NAT64_ENOMEM:
		return "RC_NAT64_ENOMEM";
	case NPF_RC_NAT64_6052:
		return "RC_NAT64_6052";
	case NPF_RC_INTL:
		break;
	};
	return "RC_INTL";
}

/*
 * return-code description
 */
const char *npf_rc_detail_str(int rc)
{
	if (rc < 0)
		rc = -rc;
	if (rc > NPF_RC_LAST)
		rc = NPF_RC_INTL;

	switch ((enum npf_rc_en)rc) {
	case NPF_RC_UNMATCHED:
		return "unmatched";
	case NPF_RC_PASS:
		return "pass";
	case NPF_RC_BLOCK:
		return "block";
	case NPF_RC_L3_HDR_VER:
		return "invalid IP header version field";
	case NPF_RC_L3_HDR_LEN:
		return "invalid IP header length field";
	case NPF_RC_NON_IP:
		return "non-IP packet";
	case NPF_RC_L3_PROTO:
		return "protocol mismatch";
	case NPF_RC_L3_SHORT:
		return "invalid layer 3 header";
	case NPF_RC_L4_SHORT:
		return "invalid layer 4 header";
	case NPF_RC_L4_PROTO:
		return "invalid layer 4 protocol";
	case NPF_RC_ICMP_ECHO:
		return "unsolicited ICMP echo reply";
	case NPF_RC_ENOSTR:
		return "unknown TCP reset";
	case NPF_RC_TCP_SYN:
		return "missing TCP SYN";
	case NPF_RC_TCP_STATE:
		return "invalid TCP flags";
	case NPF_RC_TCP_WIN:
		return "TCP window error";
	case NPF_RC_SESS_ENOMEM:
		return "no memory to create session";
	case NPF_RC_SESS_LIMIT:
		return "session limiter";
	case NPF_RC_SESS_HOOK:
		return "session hook";
	case NPF_RC_DP_SESS_ESTB:
		return "failed to create dataplane session";
	case NPF_RC_MBUF_ENOMEM:
		return "failed to allocate packet memory";
	case NPF_RC_MBUF_ERR:
		return "failed to prepend or adjust packet buffer";
	case NPF_RC_NAT_ENOSPC:
		return "failed to get NAT port mapping";
	case NPF_RC_NAT_ENOMEM:
		return "no memory to create NAT";
	case NPF_RC_NAT_EADDRINUSE:
		return "fragmented NAT port map";
	case NPF_RC_NAT_ERANGE:
		return "NAT port range too small";
	case NPF_RC_NAT_E2BIG:
		return "unable to fragment packet";
	case NPF_RC_ICMP_ERR_NAT:
		return "failed to translate ICMP error embedded pkt";
	case NPF_RC_ALG_EEXIST:
		return "ALG race condition";
	case NPF_RC_ALG_ERR:
		return "ALG error";
	case NPF_RC_NAT64_4T6:
		return "IPv4 to IPv6";
	case NPF_RC_NAT64_6T4:
		return "IPv6 to IPv4";
	case NPF_RC_NAT64_ENOSPC:
		return "Failed to get NAT64 port mapping";
	case NPF_RC_NAT64_ENOMEM:
		return "Failed to allocate NAT64 memory";
	case NPF_RC_NAT64_6052:
		return "failed to extract or encode rfc6052 NAT64 addr";
	case NPF_RC_INTL:
		break;
	};
	return "internal error";
}

/*
 * Get count for one return-code in one direction
 */
static uint64_t
npf_rc_read(struct npf_rc_counts *rcc, enum npf_rc_type rct,
	    enum npf_rc_dir dir, enum npf_rc_en rc)
{
	uint64_t sum;
	uint i;

	if (rc >= NPF_RC_SZ || dir >= NPF_DIR_SZ || rct >= NPF_RCT_SZ || !rcc)
		return 0UL;

	sum = 0UL;
	FOREACH_DP_LCORE(i)
		sum += rcc[i].type[rct].dir[dir].count[rc];

	return sum;
}

static uint64_t
npf_rc_total(struct npf_rc_counts *rcc, enum npf_rc_type opt_rct,
	     enum npf_rc_dir opt_dir, enum rc_ctrl_cat opt_cat)
{
	enum npf_rc_type rct;
	enum npf_rc_dir dir;
	enum npf_rc_en rc;
	uint64_t total = 0ul;

	/* For each return code type */
	for (rct = 0; rct < NPF_RCT_SZ; rct++) {
		if (opt_rct != NPF_RCT_ALL && opt_rct != rct)
			continue;

		/* For each direction */
		for (dir = 0; dir < NPF_DIR_SZ; dir++) {
			if (opt_dir != NPF_DIR_ALL && opt_dir != dir)
				continue;

			/* For each count */
			for (rc = 0; rc <= NPF_RC_LAST; rc++) {
				if (opt_cat != RC_CAT_ALL &&
				    opt_cat != npf_rc_ctrl[dir][rc].cat)
					continue;
				total += npf_rc_read(rcc, rct, dir, rc);
			}
		}
	}

	return total;
}

/* Show/clear command context */
struct rcc_ctx {
	json_writer_t		*ctx_json;
	enum npf_rc_type	ctx_rct;
	enum npf_rc_dir		ctx_dir;
	enum rc_ctrl_cat	ctx_cat;
	struct ifnet		*ctx_ifp;
	bool			ctx_nonzero_only;
	bool			ctx_detail;
	bool			ctx_brief;
	bool			ctx_rpc;
};

/*
 * Write detailed json for npf return code counters in one direction
 */
static void
npf_show_rc_dir_detail(json_writer_t *json, struct npf_rc_counts *rcc,
		       enum npf_rc_type rct, enum npf_rc_dir dir,
		       enum rc_ctrl_cat cat, struct rcc_ctx *ctx)
{
	enum npf_rc_en rc;
	uint64_t count;
	bool exception = false;

	/*
	 * We make an exception for nat64, and always return the ipv4-to-ipv6
	 * and ipv6-to-ipv4 counts
	 */
	if (rct == NPF_RCT_NAT64 && cat == RC_CAT_PASS)
		exception = true;

	if (!ctx->ctx_detail && !exception)
		return;

	jsonw_name(json, "detail");
	jsonw_start_object(json);

	for (rc = 0; rc <= NPF_RC_LAST; rc++) {
		if (cat != npf_rc_ctrl[dir][rc].cat)
			continue;

		/* In this count enabled for this rc-type? */
		if (!npf_rc_enabled(rct, dir, rc))
			continue;

		count = npf_rc_read(rcc, rct, dir, rc);
		jsonw_uint_field(json, npf_rc_str(rc), count);
	}
	jsonw_end_object(json); /* detail */
}

static void
npf_show_rc_dir_detail_rpc(json_writer_t *json, struct npf_rc_counts *rcc,
			   enum npf_rc_type rct, enum npf_rc_dir dir,
			   enum rc_ctrl_cat cat)
{
	uint64_t count;

	/* We initially only return two NAT64 'in' 'pass' detailed counts */
	if (rct == NPF_RCT_NAT64 && cat == RC_CAT_PASS && dir == NPF_RC_IN) {

		jsonw_name(json, "detail");
		jsonw_start_object(json);

		count = npf_rc_read(rcc, rct, dir, NPF_RC_NAT64_4T6);
		jsonw_uint_field(json, "ipv4-to-ipv6", count);

		count = npf_rc_read(rcc, rct, dir, NPF_RC_NAT64_6T4);
		jsonw_uint_field(json, "ipv6-to-ipv4", count);

		jsonw_end_object(json);
	}
}

/*
 * Write json for npf return code counters in one direction
 */
static void
npf_show_rc_counts_dir(json_writer_t *json, struct npf_rc_counts *rcc,
		       enum npf_rc_type rct, enum npf_rc_dir dir,
		       const char *name, struct rcc_ctx *ctx)
{
	enum rc_ctrl_cat cat;
	uint64_t count;

	jsonw_name(json, name);
	jsonw_start_object(json);

	/* For each off pass, unmatched, block and drop */
	for (cat = 0; cat < RC_CAT_SZ; cat++) {
		if (ctx->ctx_cat != RC_CAT_ALL && ctx->ctx_cat != cat)
			continue;

		const char *cat_name = rc_ctrl_cat2str(cat);

		/* Total for this category */
		count = npf_rc_total(rcc, rct, dir, cat);

		jsonw_name(json, cat_name);
		jsonw_start_object(json);

		jsonw_uint_field(json, "count", count);

		/* Conditionally show individual counts */
		if (ctx->ctx_rpc)
			npf_show_rc_dir_detail_rpc(json, rcc, rct, dir, cat);
		else
			npf_show_rc_dir_detail(json, rcc, rct, dir, cat, ctx);

		jsonw_end_object(json); /* cat_name */
	}

	jsonw_end_object(json);
}

/*
 * Is the rc type feature enabled on the given interface?
 */
static bool
npf_rct_is_feature_enabled(enum npf_rc_type rct, struct ifnet *ifp)
{
	const struct npf_if *nif = rcu_dereference(ifp->if_npf);
	const struct npf_config *npf_config = npf_if_conf(nif);

	switch (rct) {
	case NPF_RCT_FW4:
		return pl_node_is_feature_enabled_by_inst(&ipv4_fw_in_feat,
							  ifp);
	case NPF_RCT_FW6:
		return pl_node_is_feature_enabled_by_inst(&ipv6_fw_in_feat,
							  ifp);

	case NPF_RCT_LOC:
		if (npf_active(npf_config, NPF_LOCAL) ||
		    npf_active(npf_global_config, NPF_LOCAL) ||
		    npf_zone_local_is_set() ||
		    npf_active(npf_config, NPF_ORIGINATE) ||
		    npf_active(npf_global_config, NPF_ORIGINATE))
			return true;
		return false;

	case NPF_RCT_L2:
		if (npf_active(npf_config, NPF_BRIDGE))
			return true;
		return false;

	case NPF_RCT_ACL4:
		return pl_node_is_feature_enabled_by_inst(&ipv4_acl_in_feat,
							  ifp);
	case NPF_RCT_ACL6:
		return pl_node_is_feature_enabled_by_inst(&ipv6_acl_in_feat,
							  ifp);
	case NPF_RCT_NAT64:
		return pl_node_is_feature_enabled_by_inst(&ipv6_nat64_in_feat,
							  ifp);
	}
	return false;
}

/*
 * Write json for npf return code counters for one interface
 */
static void npf_show_rc_counts_intf(struct ifnet *ifp, void *arg)
{
	struct rcc_ctx *ctx = arg;
	struct npf_rc_counts *rcc;
	enum npf_rc_type rct;
	enum npf_rc_dir dir;
	json_writer_t *json;
	bool first_rct = true;

	if (is_lo(ifp))
		return;

	rcc = npf_if_get_rcc(ifp);
	if (!rcc || !ctx)
		return;

	uint64_t total;

	total = npf_rc_total(rcc, ctx->ctx_rct, ctx->ctx_dir, ctx->ctx_cat);
	if (!total && ctx->ctx_nonzero_only)
		return;

	json = ctx->ctx_json;

	for (rct = 0; rct < NPF_RCT_SZ; rct++) {
		if (ctx->ctx_rct != NPF_RCT_ALL && ctx->ctx_rct != rct)
			continue;

		if (!npf_rct_is_feature_enabled(rct, ifp))
			continue;

		/* Check totals for this rc-type */
		total = npf_rc_total(rcc, rct, ctx->ctx_dir, ctx->ctx_cat);
		if (!total && ctx->ctx_nonzero_only)
			continue;

		if (first_rct) {
			jsonw_start_object(json);
			jsonw_string_field(json, "name", ifp->if_name);
			first_rct = false;
		}

		jsonw_name(json, npf_rct_str(rct));
		jsonw_start_object(json);

		for (dir = 0; dir < NPF_DIR_SZ; dir++) {
			if (ctx->ctx_dir != NPF_DIR_ALL &&
			    ctx->ctx_dir != dir)
				continue;

			npf_show_rc_counts_dir(json, rcc, rct, dir,
					       npf_rc_dir_str(dir),
					       ctx);
		}

		jsonw_end_object(json); /* rct */
	}

	if (!first_rct)
		jsonw_end_object(json); /* if_name */
}

/*
 * Parse show/clear command arguments
 */
static int
npf_rc_counts_parse(FILE *f, int argc, char **argv, struct rcc_ctx *ctx)
{
	/* Default context/arguments */
	ctx->ctx_json = NULL;
	ctx->ctx_rct = NPF_RCT_ALL;
	ctx->ctx_dir = NPF_DIR_ALL;
	ctx->ctx_cat = RC_CAT_ALL;
	ctx->ctx_ifp = NULL;
	ctx->ctx_nonzero_only = false;
	ctx->ctx_detail = false;
	ctx->ctx_brief = false;
	ctx->ctx_rpc = false;

	/* All command options are in pairs */
	while (argc > 1) {

		if (!strcmp(argv[0], "type")) {
			ctx->ctx_rct = npf_rct_str2enum(argv[1]);

		} else if (!strcmp(argv[0], "interface")) {
			ctx->ctx_ifp = dp_ifnet_byifname(argv[1]);

			if (!ctx->ctx_ifp) {
				npf_cmd_err(f, "%s",
					    "invalid interface %s", argv[1]);
				return -EINVAL;
			}

		} else if (!strcmp(argv[0], "dir")) {
			if (!strcasecmp(argv[1], "in"))
				ctx->ctx_dir = NPF_RC_IN;
			else if (!strcasecmp(argv[1], "out"))
				ctx->ctx_dir = NPF_RC_OUT;

		} else if (!strcmp(argv[0], "cat")) {
			enum rc_ctrl_cat cat;

			for (cat = 0; cat < RC_CAT_SZ; cat++) {
				if (!strcasecmp(argv[1],
						rc_ctrl_cat2str(cat))) {
					ctx->ctx_cat = cat;
					break;
				}
			}

		} else if (!strcmp(argv[0], "nonzero")) {
			if (!strcasecmp(argv[1], "true") ||
			    !strcmp(argv[1], "1"))
				ctx->ctx_nonzero_only = true;

		} else if (!strcmp(argv[0], "detail")) {
			if (!strcasecmp(argv[1], "true") ||
			    !strcmp(argv[1], "1"))
				ctx->ctx_detail = true;

		} else if (!strcmp(argv[0], "brief")) {
			if (!strcasecmp(argv[1], "true") ||
			    !strcmp(argv[1], "1"))
				ctx->ctx_brief = true;

		} else if (!strcmp(argv[0], "rpc")) {
			if (!strcasecmp(argv[1], "true") ||
			    !strcmp(argv[1], "1"))
				ctx->ctx_rpc = true;
		}
		/* Silently ignore unknown options */

		argc -= 2;
		argv += 2;
	}

	return 0;
}

/*
 * Write json for npf return code counters for one or all interfaces
 *
 * [npf-op rc show counters] interface <name> type <type> detail {true|false}
 *                           brief {true|false} nonzero {true|false}
 */
int npf_show_rc_counts(FILE *f, int argc, char **argv)
{
	struct rcc_ctx ctx = { 0 };
	json_writer_t *json;
	int rc;

	/* ctrl is only used for show output, so init onetime here */
	npf_rc_ctrl_init();

	/* Parse the arguments */
	rc = npf_rc_counts_parse(f, argc, argv, &ctx);
	if (rc < 0)
		return rc;

	json = jsonw_new(f);
	if (!json)
		return -EINVAL;

	ctx.ctx_json = json;
	jsonw_pretty(json, true);

	jsonw_name(json, "npf-rc-counts");
	jsonw_start_object(json);

	jsonw_name(json, "interfaces");
	jsonw_start_array(json);

	if (ctx.ctx_ifp)
		npf_show_rc_counts_intf(ctx.ctx_ifp, &ctx);
	else
		dp_ifnet_walk(npf_show_rc_counts_intf, &ctx);

	jsonw_end_array(json);	/* interfaces */
	jsonw_end_object(json);	/* npf-rc-counts */
	jsonw_destroy(&json);
	return 0;
}

static void npf_clear_rc_counts_intf(struct ifnet *ifp, void *arg)
{
	struct rcc_ctx *ctx = arg;
	struct npf_rc_counts *rcc;
	enum npf_rc_type rct;
	enum npf_rc_dir dir;
	enum npf_rc_en rc;
	uint i;

	rcc = npf_if_get_rcc(ifp);
	if (!rcc || !ctx)
		return;

	/* For each core .. */
	FOREACH_DP_LCORE(i)
		/* For each rc type .. */
		for (rct = 0; rct < NPF_RCT_SZ; rct++) {
			if (ctx->ctx_rct != NPF_RCT_ALL && ctx->ctx_rct != rct)
				continue;

			/* For 'inbound' and 'outbound' .. */
			for (dir = 0; dir < NPF_DIR_SZ; dir++) {
				if (ctx->ctx_dir != NPF_DIR_ALL &&
				    ctx->ctx_dir != dir)
					continue;

				/* For each return code count .. */
				for (rc = 0; rc < NPF_RC_SZ; rc++) {
					enum rc_ctrl_cat cat;

					cat = npf_rc_ctrl[dir][rc].cat;
					if (ctx->ctx_cat != RC_CAT_ALL &&
					    ctx->ctx_cat != cat)
						continue;

					rcc[i].type[rct].dir[dir].count[rc] =
						0UL;
				}
			}
		}

}

/*
 * Clear return code counters
 *
 * [npf-op rc clear counters] vrf <id> type <type>
 */
int npf_clear_rc_counts(FILE *f, int argc, char **argv)
{
	struct rcc_ctx ctx = { 0 };
	int rc;

	/* Parse the arguments */
	rc = npf_rc_counts_parse(f, argc, argv, &ctx);
	if (rc < 0)
		return rc;

	if (ctx.ctx_ifp)
		npf_clear_rc_counts_intf(ctx.ctx_ifp, &ctx);
	else
		dp_ifnet_walk(npf_clear_rc_counts_intf, &ctx);

	return 0;
}

