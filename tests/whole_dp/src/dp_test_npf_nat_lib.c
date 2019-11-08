/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dp test npf NAT library
 */

#include <libmnl/libmnl.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

#include "dp_test.h"
#include "dp_test_str.h"
#include "dp_test_lib.h"
#include "dp_test_lib_intf.h"
#include "dp_test_lib_exp.h"
#include "dp_test_pktmbuf_lib.h"
#include "dp_test_netlink_state.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"
#include "dp_test_npf_lib.h"
#include "dp_test_npf_nat_lib.h"
#include "dp_test_npf_sess_lib.h"

/*
 * Destination NAT is applied inbound on an interface.
 *
 * Source NAT is applied outbound on an interface.
 *
 * Source NAT example:
 *   npf-ut add snat:<ifname> <rule>  nat-type=snat [trans-addr=<trans-addr>]
 *     [trans-port <trans-port>] action=accept [proto=<proto>]
 *     [src-addr=<address>[/<mask>]] [src-port=<port>]
 *     [dst-addr=<address>[/<mask>]] [dst-port=<port>]
 *
 * Destination NAT example:
 *   npf-ut add dnat:<ifname> <rule>  nat-type=dnat [trans-addr=<trans-addr>]
 *     [trans-port <trans-port>] action=accept [proto=<proto>]
 *     [src-addr=<address>[/<mask>]] [src-port=<port>]
 *     [dst-addr=<address>[/<mask>]] [dst-port=<port>]
 */

static bool dp_test_npf_nat_debug;

void dp_test_npf_nat_set_debug(bool on)
{
	dp_test_npf_nat_debug = on;
}

bool dp_test_npf_nat_get_debug(void)
{
	return dp_test_npf_nat_debug;
}

static const char *str_or_any(const char *str)
{
	return str ?: "any";
}

static const char *snat_or_dnat(bool snat)
{
	return snat ? "SNAT" : "DNAT";
}

/*
 * Determine what the npf rule map string should be for the "npf-ut add
 * .." command.
 *
 * Write to the provided string.  Return number of chars written (similar to
 * snprintf).
 */
static uint
dp_test_npf_nat_map_cmd(char *str, size_t len,
			const struct dp_test_npf_nat_rule_t *nat, bool snat)
{
	char trans_range[DP_TEST_IPSTR_TO_RANGE_MIN_LEN];
	const char *trans_addr = nat->trans_addr;
	uint l = 0;

	str[0] = '\0';

	/*
	 * Calculate 'map' string to be used in "npf-ut add .."
	 * request
	 */
	l += spush(str, len-l, "nat-type=%s ", snat ? "snat" : "dnat");

	if (!strcmp(nat->map, "exclude")) {
		spush(str+l, len-l, "nat-exclude=y");
		return l;
	}

	if (strcmp(nat->map, "nopinhole") != 0)
		l += spush(str+l, len-l, "nat-pinhole=y ");

	if (nat->trans_addr) {
		if (!strcmp(nat->trans_addr, "masquerade"))
			l += spush(str+l, len-l, "trans-addr-masquerade=y ");
		else {
			if (strchr(trans_addr, '/')) {
				dp_test_ipstr_to_range(trans_addr, trans_range,
						       sizeof(trans_range));
				trans_addr = trans_range;
			}
			l += spush(str+l, len-l, "trans-addr=%s ", trans_addr);
		}
	} else
		l += spush(str+l, len-l, "trans-addr=%s ", NAT_TRANS_ADDR);

	if (nat->trans_port == NULL) {
		if (nat->proto == IPPROTO_TCP || nat->proto == IPPROTO_UDP)
			l += spush(str+l, len-l, "trans-port=1-65535 ");
	} else
		l += spush(str+l, len-l, "trans-port=%s ", nat->trans_port);

	return l;
}

/*
 * Determine what the npf rule match string should be for the "npf-ut add
 * .." command.
 *
 * Write to the provided string.  Return number of chars written (similar to
 * snprintf).
 */
static uint
dp_test_npf_nat_match_cmd(char *str, size_t len,
			  const struct dp_test_npf_nat_rule_t *nat, bool snat)
{
	size_t l = 0;
	const char *from_addr = nat->from_addr;
	const char *to_addr = nat->to_addr;

	str[0] = '\0';

	/*
	 * Calculate 'match' string to be used in "npf-ut add .."
	 * request
	 */

	if (nat->proto != NAT_NULL_PROTO)
		l += spush(str+l, len-l, "proto=%d ", nat->proto);

	if (from_addr != NULL) {
		if (strchr(from_addr, ':') || strchr(from_addr, '.'))
			l += spush(str+l, len-l, "src-addr=%s ", from_addr);
		else /* not an IP address, so should be a resource group */
			l += spush(str+l, len-l, "src-addr-group=%s ",
				   from_addr);
	}

	if (nat->from_port) {
		if (isdigit(nat->from_port[0])) /* starts with a number */
			l += spush(str+l, len-l, "src-port=%s ",
				   nat->from_port);
		else	/* should be a resource group */
			l += spush(str+l, len-l, "src-port-group=%s ",
				   nat->from_port);
	}

	if (to_addr != NULL) {
		if (strchr(to_addr, ':') || strchr(to_addr, '.'))
			l += spush(str+l, len-l, "dst-addr=%s ", to_addr);
		else /* not an IP address, so should be a resource group */
			l += spush(str+l, len-l, "dst-addr-group=%s ",
				   to_addr);
	}

	if (nat->to_port) {
		if (isdigit(nat->to_port[0])) /* starts with a number */
			l += spush(str+l, len-l, "dst-port=%s ",
				   nat->to_port);
		else	/* should be a resource group */
			l += spush(str+l, len-l, "dst-port-group=%s ",
				   nat->to_port);
	}

	return l;
}

/*
 * Add a NAT rule
 */
void
_dp_test_npf_nat_add(const struct dp_test_npf_nat_rule_t *nat, bool snat,
		     bool verify, const char *file, int line)
{
	char rifname[IFNAMSIZ];
	char match[100];
	char map[100];
	uint l;

	dp_test_intf_real(nat->ifname, rifname);

	_dp_test_fail_unless(nat->proto == NAT_NULL_PROTO ||
			     (nat->proto >= 0 && nat->proto <= 255),
			     file, line,
			     "\nProtocol must be "
			     " must be NAT_NULL_PROTO or 0-255\n");

	if (nat->proto != IPPROTO_TCP && nat->proto != IPPROTO_UDP)
		if (nat->from_port != NULL || nat->to_port != NULL)
			_dp_test_fail(file, line,
				      "\nSource and dest ports"
				      " must be NULL for non TCP/UDP rules\n");
	/*
	 * Format nat 'map' string
	 */
	l = dp_test_npf_nat_map_cmd(map, sizeof(map), nat, snat);
	_dp_test_fail_unless(l < sizeof(map), file, line,
			     "nat map string exceeded buffer space");


	/*
	 * Format nat 'match' string
	 */
	l = dp_test_npf_nat_match_cmd(match, sizeof(match), nat, snat);
	_dp_test_fail_unless(l < sizeof(match), file, line,
			     "nat match string exceeded buffer space");


	/* Put it all together */
	char cmd[TEST_MAX_CMD_LEN];

	spush(cmd, sizeof(cmd), "npf-ut add %s:%s %s action=accept %s %s",
	      snat ? "snat" : "dnat", rifname, nat->rule, map, match);

	if (dp_test_npf_nat_debug)
		printf("cmd: %s\n", cmd);

	_dp_test_npf_cmd(cmd, false, file, line);

	dp_test_npf_commit();

	if (verify)
		_dp_test_npf_nat_verify(nat, snat, false, file, line);
}

/*
 * Delete a NAT rule
 */
void
_dp_test_npf_nat_del(const char *ifname, const char *rule, bool snat,
		     bool verify, const char *file, int line)
{
	char cmd[TEST_MAX_CMD_LEN];
	char dp_rule[6];
	char rifname[IFNAMSIZ];

	dp_test_intf_real(ifname, rifname);

	spush(dp_rule, sizeof(dp_rule), "%s", rule);

	spush(cmd, TEST_MAX_CMD_LEN,
	      "npf-ut delete %s:%s %s",
	      snat ? "snat" : "dnat", rifname, dp_rule);

	_dp_test_npf_cmd(cmd, false, file, line);

	dp_test_npf_commit();

	if (!verify)
		return;

	json_object *jrule;

	jrule = dp_test_npf_json_get_nat_rule(rifname, rule, snat);
	if (jrule) {
		json_object_put(jrule);
		_dp_test_fail(file, line,
			      "\nFailed to delete %s NAT rule %s\n",
			      snat_or_dnat(snat), rule);
	}
}

/*
 * Determine what the npf rule "match" field should be in the "npf-op show"
 * request json reply.
 *
 * Write to the provided string.  Return number of chars written (similar to
 * snprintf).
 */
static uint
dp_test_npf_nat_match_list(char *str, size_t len,
			   const struct dp_test_npf_nat_rule_t *nat, bool snat)
{
	size_t l = 0;

	str[0] = '\0';

	/*
	 * Calculate 'match' string returned in "npf-op fw list" request.
	 *
	 * Note the trailing space at the end of the string.
	 */
	if (nat->proto != NAT_NULL_PROTO)
		l += spush(str+l, len-l, "proto %d ", nat->proto);

	if (nat->from_addr || nat->from_port) {
		l += spush(str+l, len-l, "from %s ",
			   str_or_any(nat->from_addr));

		if (nat->from_port)
			l += spush(str+l, len-l, "port %s ",
				   nat->from_port);
	}

	if (nat->to_addr || nat->to_port) {
		l += spush(str+l, len-l, "to %s ",
			   str_or_any(nat->to_addr));

		if (nat->to_port)
			l += spush(str+l, len-l, "port %s ",
				   nat->to_port);
	}

	return l;
}

/*
 * Determine what the npf rule "map" field should be for the "npf-op show"
 * request json reply.
 *
 * Write to the provided string.  Return number of chars written (similar to
 * snprintf).
 */
static uint
dp_test_npf_nat_map_list(char *str, size_t len,
			 const struct dp_test_npf_nat_rule_t *nat, bool snat)
{
	char trans_port[20];
	char trans_range[DP_TEST_IPSTR_TO_RANGE_MIN_LEN];
	const char *trans_addr = nat->trans_addr;
	uint l = 0;

	str[0] = '\0';

	/*
	 * Calculate 'map' string returned in "npf-op show" request
	 */
	if (!strcmp(nat->map, "exclude")) {
		l += spush(str+l, len-l, "%s", nat->map);
		return l;
	}

	if (strcmp(nat->map, "nopinhole") != 0)
		l += spush(str+l, len-l, "%s", "pinhole ");

	if (trans_addr == NULL)
		trans_addr = "0.0.0.0-255.255.255.255";

	if (strchr(trans_addr, '/')) {
		dp_test_ipstr_to_range(trans_addr, trans_range,
				       sizeof(trans_range));
		trans_addr = trans_range;
	}

	if (nat->proto == IPPROTO_TCP || nat->proto == IPPROTO_UDP) {
		if (nat->trans_port == NULL)
			spush(trans_port, sizeof(trans_port),
			      " port 1-65535");
		else if (strchr(nat->trans_port, '-'))
			spush(trans_port, sizeof(trans_port),
			      " port %s", nat->trans_port);
		else
			spush(trans_port, sizeof(trans_port),
			      " port %s-%s", nat->trans_port,
			      nat->trans_port);
	} else {
		trans_port[0] = '\0';
	}

	if (snat)
		l += spush(str+l, len-l, "dynamic any -> %s%s",
			   trans_addr, trans_port);
	else
		l += spush(str+l, len-l, "dynamic %s%s <- any",
			   trans_addr, trans_port);

	return l;
}

#define INDENT 4

void
_dp_test_npf_nat_verify(const struct dp_test_npf_nat_rule_t *nat, bool snat,
			bool print, const char *file, int line)
{
	char real_ifname[IFNAMSIZ];
	char buf[TEST_MAX_CMD_LEN];
	json_object *jrule;
	const char *str = NULL;
	bool rb;
	int ri;

	dp_test_intf_real(nat->ifname, real_ifname);

	jrule = dp_test_npf_json_get_nat_rule(real_ifname, nat->rule, snat);
	_dp_test_fail_unless(jrule != NULL, file, line,
			     "\nFailed to find %s rule %s\n",
			     snat_or_dnat(snat), nat->rule);

	if (dp_test_npf_nat_debug) {
		str = json_object_to_json_string_ext(jrule,
						     JSON_C_TO_STRING_PRETTY);
		printf("%s rule %s \"%s\"\n",
		       snat_or_dnat(snat), nat->rule, nat->desc);
		printf("%s\n", str);
	}


	/* Verify "map" field.
	 *
	 * Use the 'buf' buffer to prepare the string we epect to see.  Then get
	 * the relevant field from the rules json object, and compare.
	 */
	dp_test_npf_nat_map_list(buf, TEST_MAX_CMD_LEN, nat, snat);

	rb = dp_test_json_string_field_from_obj(jrule, "map", &str);
	_dp_test_fail_unless(rb, file, line,
			     "\n%s rule %s, Failed to find \"map\" field\n",
			     snat_or_dnat(snat), nat->rule);

	ri = strcmp(str, buf);
	_dp_test_fail_unless(ri == 0, file, line,
			     "\n%s rule %s \"map\" field\n"
			     "expected \"%s\"\n"
			     "found    \"%s\"\n",
			     snat_or_dnat(snat), nat->rule, buf, str);

	/* Verify "match" field.
	 *
	 * Use the 'buf' buffer to prepare the string we epect to see.  Then get
	 * the relevant field from the rules json object, and compare.
	 */
	dp_test_npf_nat_match_list(buf, TEST_MAX_CMD_LEN, nat, snat);

	rb = dp_test_json_string_field_from_obj(jrule, "match", &str);
	_dp_test_fail_unless(rb, file, line,
			     "\n%s rule %s, Failed to find \"match\" field\n",
			     snat_or_dnat(snat), nat->rule);

	ri = strcmp(str, buf);
	_dp_test_fail_unless(ri == 0, file, line,
			     "\n%s rule %s \"match\" field\n"
			     "expected \"%s\"\n"
			     "found    \"%s\"\n",
			     snat_or_dnat(snat), nat->rule, buf, str);

	json_object_put(jrule);
}

/*
 * Get packet count from a NAT rule. Returns true if successful.
 */
bool
dp_test_npf_nat_get_pkts(const char *real_ifname, const char *rule, bool snat,
			 uint *packets)
{
	json_object *jrule;
	bool rv;

	jrule = dp_test_npf_json_get_nat_rule(real_ifname, rule, snat);
	if (!jrule)
		return false;

	rv = dp_test_json_int_field_from_obj(jrule, "packets", (int *)packets);

	json_object_put(jrule);
	return rv;
}

/*
 * Verify the packet count of a NAT rule
 */
void
_dp_test_npf_nat_verify_pkts(const char *ifname, const char *rule, bool snat,
			     uint exp_pkts, const char *file, int line)
{
	bool rv;
	uint pkts = 0;
	char real_ifname[IFNAMSIZ];

	dp_test_intf_real(ifname, real_ifname);

	rv = dp_test_npf_nat_get_pkts(real_ifname, rule, snat, &pkts);

	_dp_test_fail_unless(rv, file, line,
			     "\nFailed to find %s rule %s\n",
			     snat_or_dnat(snat), rule);

	_dp_test_fail_unless(pkts == exp_pkts, file, line,
			     "\n%s rule %s exp pkts %d, "
			     "actual %d\n",
			     snat_or_dnat(snat), rule, exp_pkts, pkts);
}

/*
 * Add a NAT64 rule using rfc6052 for source and dest translation
 *
 * This is similar as to how the old nat64 config is converted to new nat64
 * dataplane commands.
 *
 * npf-ut add nat64:NAT64_ 1
 *    src-addr=2001:101:1::/64 dst-addr=2001:101:2::/64
 *    handle=nat64(stype=rfc6052,spl=96,dtype=rfc6052,dpl=96)
 */
void
_dp_test_npf_nat64_add(const struct dp_test_npf_nat64_rule_t *rule,
		       bool verify, const char *file, int line)
{
	char real_ifname[IFNAMSIZ];
	char cmd[TEST_MAX_CMD_LEN];
	char group[100];

	dp_test_intf_real(rule->ifname, real_ifname);
	snprintf(group, sizeof(group), "_NAT64_%s", real_ifname);

	/*
	 * There is a conversion utility in npf_cmd.c to convert the old-style
	 * nat64 command to the new command.  This just allows old config to
	 * not cause an error, and is expected to only be temporary until
	 * vplane-config-npf is updated.
	 *
	 * However for the unit-tests we add the attach/detach to ensure it
	 * works.
	 */
	spush(cmd, TEST_MAX_CMD_LEN,
	      "npf-ut add nat64:%s %s action=accept src-addr=%s dst-addr=%s "
	      "handle=nat64("
	      "stype=rfc6052,spl=%u,dtype=rfc6052,dpl=%u)",
	      group, rule->rule, rule->from_addr,
	      rule->to_addr, rule->spl, rule->dpl);

	_dp_test_npf_cmd(cmd, false, file, line);
	dp_test_npf_commit();

	_dp_test_npf_cmd_fmt(
		false, file, line,
		"npf-ut attach interface:%s nat64 nat64:%s",
		real_ifname, group);
	dp_test_npf_commit();
}

/*
 * Delete a NAT64 rule
 */
void
_dp_test_npf_nat64_del(const struct dp_test_npf_nat64_rule_t *rule,
		       bool verify, const char *file, int line)
{
	char real_ifname[IFNAMSIZ];
	char cmd[TEST_MAX_CMD_LEN];
	char group[100];

	dp_test_intf_real(rule->ifname, real_ifname);
	snprintf(group, sizeof(group), "_NAT64_%s", real_ifname);

	_dp_test_npf_cmd_fmt(
		false, file, line,
		"npf-ut detach interface:%s nat64 nat64:%s",
		real_ifname, group);
	dp_test_npf_commit();

	spush(cmd, TEST_MAX_CMD_LEN, "npf-ut delete nat64:%s",
	      group);

	_dp_test_npf_cmd(cmd, false, file, line);
}


/*
 * NAT validation context helper functions
 */

static void
dp_test_npf_nat_ctx_set_desc(struct dp_test_nat_ctx *ctx)
{
	spush(ctx->desc, sizeof(ctx->desc), "%sNAT %s",
	      ctx->dnat ? "D" : "S",
	      ctx->dir == DP_TEST_NAT_DIR_FORW ? "Forw" : "Back");
}

/*
 *
 */
void
dp_test_npf_nat_ctx_set_dnat(struct dp_test_nat_ctx *ctx)
{
	ctx->dnat = true;
	dp_test_npf_nat_ctx_set_desc(ctx);
}

void
dp_test_npf_nat_ctx_set_snat(struct dp_test_nat_ctx *ctx)
{
	ctx->dnat = false;
	dp_test_npf_nat_ctx_set_desc(ctx);
}

void
dp_test_npf_nat_ctx_set_dir(struct dp_test_nat_ctx *ctx,
			    enum dp_test_nat_dir dir)
{
	ctx->dir = dir;
	dp_test_npf_nat_ctx_set_desc(ctx);
}

void
dp_test_npf_nat_ctx_set_oaddr(struct dp_test_nat_ctx *ctx, uint32_t oaddr)
{
	ctx->oaddr = oaddr;

	if (!inet_ntop(AF_INET, &oaddr, ctx->oaddr_str,
		       sizeof(ctx->oaddr_str)))
		spush(ctx->oaddr_str, sizeof(ctx->oaddr_str), "0x%X", oaddr);
}

void
dp_test_npf_nat_ctx_set_oaddr_str(struct dp_test_nat_ctx *ctx,
				  const char *oaddr_str)
{
	strncpy(ctx->oaddr_str, oaddr_str, sizeof(ctx->oaddr_str) - 1);
	ctx->oaddr_str[sizeof(ctx->oaddr_str) - 1] = '\0';
	inet_pton(AF_INET, oaddr_str, &ctx->oaddr);
}

void
dp_test_npf_nat_ctx_set_taddr(struct dp_test_nat_ctx *ctx, uint32_t taddr)
{
	ctx->taddr = taddr;

	if (!inet_ntop(AF_INET, &taddr, ctx->taddr_str,
		       sizeof(ctx->taddr_str)))
		spush(ctx->taddr_str, sizeof(ctx->taddr_str), "0x%X", taddr);
}

void
dp_test_npf_nat_ctx_set_taddr_str(struct dp_test_nat_ctx *ctx,
				  const char *taddr_str)
{
	strncpy(ctx->taddr_str, taddr_str, sizeof(ctx->taddr_str) - 1);
	ctx->taddr_str[sizeof(ctx->taddr_str) - 1] = '\0';
	inet_pton(AF_INET, taddr_str, &ctx->taddr);
}

void
dp_test_npf_nat_ctx_set_oport(struct dp_test_nat_ctx *ctx, uint16_t oport)
{
	ctx->oport = oport;
	spush(ctx->oport_str, sizeof(ctx->oport_str), "%u", ctx->oport);
}

void
dp_test_npf_nat_ctx_set_tport(struct dp_test_nat_ctx *ctx, uint16_t tport,
			      uint16_t tport_end)
{
	ctx->tport = tport;
	ctx->tport_end = tport_end;
	spush(ctx->tport_str, sizeof(ctx->tport_str), "%u", ctx->tport);
	spush(ctx->tport_end_str, sizeof(ctx->tport_end_str), "%u",
	      ctx->tport_end);
}

/*
 * Setup NAT context for packet verification.  For convenience we derive the
 * NAT config from the pre and post NAT packet descriptors.
 *
 * This NAT context is used in three different verifications:
 *
 * 1. The session verification uses the pre and post packet descriptors,
 *
 * 2. NAT translation in the IP header verification uses oaddr/taddr and
 *    oport/tport variables, and
 *
 * 3. ALG verification uses the oaddr_str/taddr_str and oport/tport variables.
 */
void
dp_test_nat_set_ctx(struct dp_test_nat_ctx *ctx,
		    enum dp_test_nat_dir dir,
		    enum dp_test_trans_type ttype,
		    struct dp_test_pkt_desc_t *pre,
		    struct dp_test_pkt_desc_t *post,
		    bool verify_session)
{
	ctx->dir = dir;
	ctx->dnat = (ttype == DP_TEST_TRANS_DNAT);
	ctx->pre = pre;
	ctx->post = post;
	ctx->verify_session = verify_session;

	uint16_t pre_src_id, pre_dst_id;
	uint16_t post_src_id, post_dst_id;

	dp_test_npf_extract_ids_from_pkt_desc(pre, &pre_src_id,
					      &pre_dst_id);
	dp_test_npf_extract_ids_from_pkt_desc(post, &post_src_id,
					      &post_dst_id);

	if (ttype == DP_TEST_TRANS_DNAT && dir == DP_TEST_NAT_DIR_FORW) {

		spush(ctx->desc, sizeof(ctx->desc), "DNAT Forw");

		dp_test_npf_nat_ctx_set_oaddr_str(ctx, pre->l3_dst);
		dp_test_npf_nat_ctx_set_oport(ctx, pre_dst_id);
		dp_test_npf_nat_ctx_set_taddr_str(ctx, post->l3_dst);
		dp_test_npf_nat_ctx_set_tport(ctx, post_dst_id, 0);
	}

	if (ttype == DP_TEST_TRANS_DNAT && dir == DP_TEST_NAT_DIR_BACK) {

		spush(ctx->desc, sizeof(ctx->desc), "DNAT Back");

		dp_test_npf_nat_ctx_set_oaddr_str(ctx, post->l3_src);
		dp_test_npf_nat_ctx_set_oport(ctx, post_src_id);
		dp_test_npf_nat_ctx_set_taddr_str(ctx, pre->l3_src);
		dp_test_npf_nat_ctx_set_tport(ctx, pre_src_id, 0);
	}

	if (ttype == DP_TEST_TRANS_SNAT && dir == DP_TEST_NAT_DIR_FORW) {

		spush(ctx->desc, sizeof(ctx->desc), "SNAT Forw");

		dp_test_npf_nat_ctx_set_oaddr_str(ctx, pre->l3_src);
		dp_test_npf_nat_ctx_set_oport(ctx, pre_src_id);
		dp_test_npf_nat_ctx_set_taddr_str(ctx, post->l3_src);
		dp_test_npf_nat_ctx_set_tport(ctx, post_src_id, 0);
	}

	if (ttype == DP_TEST_TRANS_SNAT && dir == DP_TEST_NAT_DIR_BACK) {

		spush(ctx->desc, sizeof(ctx->desc), "SNAT Back");

		dp_test_npf_nat_ctx_set_oaddr_str(ctx, post->l3_dst);
		dp_test_npf_nat_ctx_set_oport(ctx, post_dst_id);
		dp_test_npf_nat_ctx_set_taddr_str(ctx, pre->l3_dst);
		dp_test_npf_nat_ctx_set_tport(ctx, pre_dst_id, 0);
	}

	ctx->flags = SE_ACTIVE;
	ctx->flags_mask = SE_FLAGS_AE;
}


/*
 * NAT validation function.  May be used for SNAT or DNAT.
 *
 * Typically this is called *after* the packet has been modified by NAT, but
 * *before* the pkt queued on the tx ring is checked.
 *
 * For bidir NAT this function may be called once for each.
 *
 * verify_session will typically only be set for ALG secondary flows where the
 * initial packet is backards relative to the parent session.
 */
bool
dp_test_nat_validate(struct rte_mbuf *mbuf, struct ifnet *ifp,
		     struct dp_test_nat_ctx *nat, char *str, int len)
{
	if (!nat || !nat->pre || !nat->post)
		return true;

	struct dp_test_pkt_desc_t *pre = nat->pre;
	struct dp_test_pkt_desc_t *post = nat->post;
	bool forw = (nat->dir == DP_TEST_NAT_DIR_FORW);

	uint16_t pre_src_id, pre_dst_id;
	uint16_t post_src_id, post_dst_id;

	dp_test_npf_extract_ids_from_pkt_desc(pre, &pre_src_id,
					      &pre_dst_id);
	dp_test_npf_extract_ids_from_pkt_desc(post, &post_src_id,
					      &post_dst_id);

	/*
	 * If possible, verify the NAT session before verifying the packet.
	 * If the session is incorrect then the packet is bound to also be
	 * incorrect.
	 */
	if (nat->verify_session) {
		const char *trans_addr, *src_addr, *dst_addr;
		uint16_t trans_port, src_id, dst_id;
		int trans_type;
		const char *intf;

		/*
		 * First determine what addresses and ports we expect to see
		 * in the NAT session
		 */
		if ((nat->dnat && forw) || (!nat->dnat && !forw)) {
			/* DNAT FORW or SNAT BACK */
			src_addr = pre->l3_src;
			src_id = pre_src_id;

			dst_addr = pre->l3_dst;
			dst_id = pre_dst_id;

			trans_addr = post->l3_dst;
			trans_port = post_dst_id;

			trans_type = TRANS_TYPE_NATIN;
			intf = pre->rx_intf;
		}

		if ((nat->dnat && !forw) || (!nat->dnat && forw)) {
			/* DNAT BACK or SNAT FORW */
			src_addr = pre->l3_src;
			src_id = pre_src_id;

			/*
			 * dst *may* have been changed by dnat if snat
			 * and dnat are configured
			 */
			dst_addr = post->l3_dst;
			dst_id = post_dst_id;

			trans_addr = post->l3_src;
			trans_port = post_src_id;

			trans_type = TRANS_TYPE_NATOUT;
			intf = pre->tx_intf;

		}

		/*
		 * Verify NAT session exists
		 */
		if (!dp_test_npf_nat_session_check(
			    NULL,
			    src_addr, src_id,
			    dst_addr, dst_id,
			    pre->proto,
			    trans_addr, trans_port,
			    trans_type, intf,
			    nat->flags, nat->flags_mask, true,
			    str, len)) {
			dp_test_npf_print_nat_sessions("NAT validate callback");
			return false;
		}
	}

	/*
	 * A common issue with unit-tests is not setting up a neighbour entry.
	 * When this is the case then the dataplane will send an ARP request.
	 * Catch this here and format a suitable error message.
	 */
	struct ether_hdr *eth;

	eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	if (eth->ether_type == htons(ETHER_TYPE_ARP)) {
		char *tpa = (char *)(eth + 1) + 24;

		spush(str, len,
		      "ARP for %s (forgot to add a neighbour entry?)",
		      inet_ntoa(*(struct in_addr *)tpa));
		return false;
	}

	/*
	 * Verify the L3 addresses and L4 ports.  We could have left this to
	 * the packet comparison mechanism, but this provides better output if
	 * something goes wrong.
	 */
	struct iphdr *ip = iphdr(mbuf);

	char saddr_str[INET_ADDRSTRLEN];
	char daddr_str[INET_ADDRSTRLEN];

	/* Convert packet addresses to strings */
	inet_ntop(AF_INET, &ip->saddr, saddr_str, sizeof(saddr_str));
	inet_ntop(AF_INET, &ip->daddr, daddr_str, sizeof(daddr_str));

	/*
	 * Check destination address for DNAT forwards or SNAT backwards
	 */
	if ((nat->dnat && forw) || (!nat->dnat && !forw)) {
		if (strcmp(daddr_str, post->l3_dst)) {
			spush(str, len, "%s, dst IP %s, expd %s",
			      nat->desc, daddr_str, post->l3_dst);
			return false;
		}
	}

	/*
	 * Check source address for SNAT forwards or DNAT back
	 */
	if ((!nat->dnat && forw) || (nat->dnat && !forw)) {
		if (strcmp(saddr_str, post->l3_src)) {
			spush(str, len, "%s, src IP %s, expd %s",
			      nat->desc, saddr_str, post->l3_src);
			return false;
		}
	}

	/*
	 * Check destination port for DNAT forwards or SNAT backwards
	 */
	if ((nat->dnat && forw) || (!nat->dnat && !forw)) {
		if (post->proto == IPPROTO_TCP ||
		    post->proto == IPPROTO_UDP) {
			struct tcphdr *tcp = (struct tcphdr *)(ip + 1);

			/* Expected dest port */
			if (post->l4.tcp.dport != 0 &&
			    post->l4.tcp.dport != ntohs(tcp->dest)) {
				spush(str, len, "%s, dst port %u, expd %u",
				      nat->desc, ntohs(tcp->dest),
				      post->l4.tcp.dport);
				return false;
			}
		}
	}

	/*
	 * Check source port for SNAT forwards or DNAT back
	 */
	if ((!nat->dnat && forw) || (nat->dnat && !forw)) {
		if (post->proto == IPPROTO_TCP ||
		    post->proto == IPPROTO_UDP) {
			struct tcphdr *tcp = (struct tcphdr *)(ip + 1);

			/* Expected source port */
			if (post->l4.tcp.sport != 0 &&
			    post->l4.tcp.sport != ntohs(tcp->source)) {
				spush(str, len, "%s, src port %u, expd %u",
				      nat->desc, ntohs(tcp->source),
				      post->l4.tcp.sport);
				return false;
			}
		}
	}

	return true;
}

/*
 * Validate port range.
 *
 * SNAT - check the source port is in the translation port range, and adjust
 * the source port in the expected packet to match the transmit packet so that
 * the subsequent packet validation passes.
 */
static bool
dp_test_nat_validate_port_range(struct rte_mbuf *m,
				struct dp_test_expected *test_exp,
				struct dp_test_nat_ctx *nat,
				char *str, int len)
{
	if (!nat->dnat && (nat->tport_end > nat->tport)) {
		struct iphdr *ip = iphdr(m);
		struct tcphdr *tcp = (struct tcphdr *)(ip + 1);

		/* fetch source port */
		uint16_t sport = ntohs(tcp->source);

		if (sport < nat->tport || sport > nat->tport_end) {
			spush(str, len, "%s, src port %u, expd %u-%u",
			      nat->desc, sport, nat->tport, nat->tport_end);
			return false;
		}

		struct rte_mbuf *exp_pak = dp_test_exp_get_pak(test_exp);

		/* update expected pak with source port */
		ip = iphdr(exp_pak);
		tcp = (struct tcphdr *)(ip + 1);

		nat->eport = sport;

		/* update source port */
		tcp->source = htons(sport);

		/* update tcp checksum */
		tcp->check = 0;
		tcp->check = dp_test_calc_udptcp_chksum(exp_pak);
	}

	return true;
}

/*
 * NAT validation callback function.  May be used for SNAT or DNAT.
 *
 * This is called *after* the packet has been modified by NAT, but *before*
 * the pkt queued on the tx ring is checked.
 */
static void
dp_test_nat_validate_cb(struct rte_mbuf *mbuf, struct ifnet *ifp,
			struct dp_test_expected *test_exp,
			enum dp_test_fwd_result_e fwd_result)
{
	struct dp_test_nat_cb_ctx *ctx;
	char err[240];

	ctx = dp_test_exp_get_validate_ctx(test_exp);

	/*
	 * Check if we need to adjust the expected packet
	 */
	if (ctx->snat && (ctx->snat->tport_end > ctx->snat->tport)) {
		/*
		 * SNAT to a port range.  Verify the source ports is in range,
		 * and set the exp packet accordingly.
		 */
		if (!dp_test_nat_validate_port_range(mbuf, test_exp, ctx->snat,
						     err, sizeof(err)))
			_dp_test_fail(ctx->file, ctx->line, "%s", err);
	}

	if (!dp_test_nat_validate(mbuf, ifp, ctx->dnat, err, sizeof(err)))
		printf("%s\n", err);

	if (!dp_test_nat_validate(mbuf, ifp, ctx->snat, err, sizeof(err)))
		printf("%s\n", err);

	/*
	 * finally, call the saved check routine (typically
	 * dp_test_pak_verify)
	 */
	if (ctx->saved_cb)
		(ctx->saved_cb)(mbuf, ifp, test_exp, fwd_result);
}

void
_dp_test_nat_set_validation(struct dp_test_nat_cb_ctx *ctx,
			    struct dp_test_expected *test_exp,
			    const char *file, int line)
{
	strncpy(ctx->file, file, sizeof(ctx->file) - 1);
	ctx->file[sizeof(ctx->file) - 1] = '\0';
	ctx->line = line;

	dp_test_exp_set_validate_ctx(test_exp, ctx, false);
	dp_test_exp_set_validate_cb(test_exp, dp_test_nat_validate_cb);
}

/*
 * Get the npf NAT json object.  json_object_put should be called once the
 * caller has finished with the returned object.
 */
static json_object *
dp_test_npf_json_nat(const char *real_ifname, const char *rs_type)
{
	json_object *jresp;
	json_object *jnat;
	struct dp_test_json_find_key key[] = { {"config", NULL},
					       {"attach_type", "interface"},
					       {"attach_point", real_ifname},
					       {"rulesets", NULL},
					       {"ruleset_type", rs_type},
					       {"groups", NULL},
					       {"rules", NULL} };
	char *response;
	bool err;

	response = dp_test_console_request_w_err("npf-op show all:",
						 &err, false);
	if (!response || err)
		return NULL;

	jresp = parse_json(response, parse_err_str, sizeof(parse_err_str));
	free(response);

	if (!jresp)
		return NULL;

	jnat = dp_test_json_find(jresp, key, ARRAY_SIZE(key));
	json_object_put(jresp);

	return jnat;
}

/*
 * Return the json object for a specific source or dest NAT rule
 *
 *	jnat = dp_test_npf_json_nat_rule(ifname, "10", true);
 *
 * The returned json object has its ref count incremented, so json_object_put
 * should be called once the caller has finished with the object.
 */
json_object *
dp_test_npf_json_get_nat_rule(const char *real_ifname, const char *rule,
			      bool snat)
{
	json_object *jnat, *jrule;

	if (snat)
		jnat = dp_test_npf_json_nat(real_ifname, "snat");
	else
		jnat = dp_test_npf_json_nat(real_ifname, "dnat");

	if (!jnat)
		return NULL;

	if (!json_object_object_get_ex(jnat, rule, &jrule))
		jrule = NULL;
	if (jrule)
		json_object_get(jrule);
	json_object_put(jnat);

	return jrule;
}

/*
 * Pretty print NAT firewall rules
 */
void
dp_test_npf_print_nat(const char *desc)
{
	json_object *jnat;
	const char *str;

	if (desc)
		printf("%s\n", desc);

	jnat = dp_test_npf_json_nat(NULL, NULL);
	if (!jnat)
		return;

	str = json_object_to_json_string_ext(jnat, JSON_C_TO_STRING_PRETTY);
	if (str)
		printf("%s\n", str);

	json_object_put(jnat);
}

/*
 * Wrapper around dp_test_pak_receive to create, send, and verify NAT'd
 * packets.
 *
 * descr	Description of the packet being sent
 * pre		pre-NAT packet descriptor
 * post		post-NAT packet descriptor (with translations)
 * dir		Direction of the packet relative to the NAT session
 *		(DP_TEST_NAT_DIR_FORW or DP_TEST_NAT_DIR_BACK)
 * ttype	DP_TEST_TRANS_SNAT, DP_TEST_TRANS_DNAT or DP_TEST_TRANS_NONE
 * verify_sess	Verify the NAT session exists during packet validation callback
 * count	Number of packets to send
 * delay	Delay in seconds between packets
 *
 * Note, the delay is for use when sending multiple packets, however this
 * should *only* be used in a private build, i.e. dont commit test code with a
 * non-zero delay.
 */
void
_dp_test_npf_nat_pak_receive(const char *descr,
			     struct dp_test_pkt_desc_t *pre,
			     struct dp_test_pkt_desc_t *post,
			     enum dp_test_nat_dir dir,
			     enum dp_test_trans_type ttype,
			     bool verify_sess,
			     uint count, uint delay,
			     const char *file, int line)
{
	struct rte_mbuf *pre_pak, *post_pak;
	struct dp_test_expected *test_exp;
	struct dp_test_nat_ctx nat_context;
	struct dp_test_nat_ctx *nctx = &nat_context;
	uint i;

	if (!descr || !pre || !post)
		_dp_test_fail(file, line, "EINVAL");

	memset(nctx, 0, sizeof(*nctx));

	/*
	 * The NAT packet verification is a wrapper around the dp-test packet
	 * verification.  It checks the IP header has been correctly NAT'd
	 * *before* the packet comparison is done.
	 */
	struct dp_test_nat_cb_ctx nat_ctx = {
		.snat = NULL,
		.dnat = NULL,
		.saved_cb = dp_test_pak_verify
	};

	if (ttype == DP_TEST_TRANS_SNAT)
		nat_ctx.snat = nctx;
	else if (ttype == DP_TEST_TRANS_DNAT)
		nat_ctx.dnat = nctx;

	/*
	 * For each packet ...
	 */
	for (i = 0; i < count; i++) {
		/*
		 * Get pre-nat and post nat packets
		 */
		pre_pak = dp_test_v4_pkt_from_desc(pre);
		post_pak = dp_test_v4_pkt_from_desc(post);
		test_exp = _dp_test_exp_from_desc(post_pak, post, NULL, 0,
						  false, file, line);
		rte_pktmbuf_free(post_pak);

		if (count == 1)
			spush(test_exp->description,
			      sizeof(test_exp->description),
			      "%s", descr);
		else
			spush(test_exp->description,
			      sizeof(test_exp->description),
			      "[%u] %s", i + 1, descr);


		dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

		/*
		 * Setup the NAT context struct, 'nctx', from the ttype, pre
		 * pkt descriptor and post pkt descriptor.  We also derive the
		 * NAT config from these.
		 */
		dp_test_nat_set_ctx(nctx, dir, ttype, pre, post,
				    i == 0 ? verify_sess : false);

		/*
		 * Setup the pkt validation callback function to
		 * dp_test_nat_validate_cb
		 */
		_dp_test_nat_set_validation(&nat_ctx, test_exp, file, line);

		/* Run the test */
		_dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp,
				     file, __func__, line);

		if (count > 1 && delay)
			sleep(delay);
	}
}
