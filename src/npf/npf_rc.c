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
#include "npf/npf_cmd.h"
#include "npf/npf_rc.h"

/*
 * Create npf counters.  A set of counters is created per npf interface.
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
	     enum npf_rc_dir opt_dir)
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
			for (rc = 0; rc <= NPF_RC_LAST; rc++)
				total += npf_rc_read(rcc, rct, dir, rc);
		}
	}

	return total;
}

/* Show/clear command context */
struct rcc_ctx {
	json_writer_t		*ctx_json;
	enum npf_rc_type	ctx_rct;
	enum npf_rc_dir		ctx_dir;
	struct ifnet		*ctx_ifp;
	bool			ctx_nonzero_only;
	bool			ctx_detail;
	bool			ctx_brief;
};

/*
 * Write json for npf return code counters in one direction
 */
static void
npf_show_rc_counts_dir(json_writer_t *json, struct npf_rc_counts *rcc,
		       enum npf_rc_type rct, enum npf_rc_dir dir,
		       const char *name, struct rcc_ctx *ctx __unused)
{
	uint64_t count;
	enum npf_rc_en rc;

	jsonw_name(json, name);
	jsonw_start_object(json);

	for (rc = 0; rc <= NPF_RC_LAST; rc++) {
		count = npf_rc_read(rcc, rct, dir, rc);
		jsonw_uint_field(json, npf_rc_str(rc), count);
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
	case NPF_RCT_L2:
		if (npf_active(npf_config, NPF_BRIDGE))
			return true;
		return false;

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

	total = npf_rc_total(rcc, ctx->ctx_rct, ctx->ctx_dir);
	if (!total && ctx->ctx_nonzero_only)
		return;

	json = ctx->ctx_json;

	for (rct = 0; rct < NPF_RCT_SZ; rct++) {
		if (ctx->ctx_rct != NPF_RCT_ALL && ctx->ctx_rct != rct)
			continue;

		if (!npf_rct_is_feature_enabled(rct, ifp))
			continue;

		/* Check totals for this rc-type */
		total = npf_rc_total(rcc, rct, ctx->ctx_dir);
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
	ctx->ctx_ifp = NULL;
	ctx->ctx_nonzero_only = false;
	ctx->ctx_detail = false;
	ctx->ctx_brief = false;

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

	/* Parse the arguments */
	rc = npf_rc_counts_parse(f, argc, argv, &ctx);
	if (rc < 0)
		return rc;

	json = jsonw_new(f);
	if (!json)
		return -EINVAL;

	ctx.ctx_json = json;
	jsonw_pretty(json, true);

	/*
	 * If an interface is *not* specified then only return interfaces that
	 * have a non-zero count
	 */

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
